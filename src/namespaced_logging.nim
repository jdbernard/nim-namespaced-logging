import std/[algorithm, json, locks, options, sequtils, strutils, tables, times]
import timeutils, zero_functional

from logging import Level
export logging.Level

type
  LogService* = ptr LogServiceObj
    ## Shareable pointer to the shared log service object.

  LogServiceObj = object
    cfg*: LogServiceConfig
    lock: Lock

  LogServiceConfig* = object
    loggers*: seq[LoggerConfig]
    appenders*: seq[LogAppender]
    rootLevel*: Level

  ThreadState = object
    cfg: LogServiceConfig
    loggers: TableRef[string, Logger]

  LoggerConfig* = object of RootObj
    name*: string
    threshold*: Option[Level]

  Logger* = object of LoggerConfig
    svc: LogService

  LogAppender* = ref object of RootObj
    ## Base type for log appenders.
    namespace*: string
    threshold*: Level

  LogMessage* = object
    scope*: string
    level*: Level
    error*: Option[ref Exception]
    timestamp*: DateTime
    message*: string
    additionalData*: JsonNode

  ConsoleLogAppender* = ref object of LogAppender
    ## Log appender that writes log messages to the console. See
    ## *initConsoleLogAppender* for a convenient way to create instances of
    ## this appender.
    formatter*: proc (msg: LogMessage): string {.gcsafe.}
      ## Formatter allows for custom formatting of log messages. The default
      ## formatter uses `formatJsonStructuredLog` to format log messages as
      ## JSON objects which are then stringified before being written to the
      ## console.
    useStderr*: bool

  CustomLogAppender* = ref object of LogAppender
    doLogMessage*: proc (msg: LogMessage) {.gcsafe.}

  #[
  # TODO: need to think throudh thread-safe IO for file logging
  FileLogAppender* = ref object of LogAppender
    file*: File
    formatter*: proc (msg: LogMessage): string {.gcsafe.}
  ]#


var threadState {.threadvar.}: ThreadState


method initThreadCopy*(app: LogAppender): LogAppender {.base, gcsafe.} =
  raise newException(CatchableError, "missing concrete implementation")


method initThreadCopy*(cla: ConsoleLogAppender): LogAppender {.gcsafe.} =
  result = ConsoleLogAppender(
    namespace: cla.namespace,
    threshold: cla.threshold,
    formatter: cla.formatter,
    useStderr: cla.useStdErr)


method initThreadCopy*(cla: CustomLogAppender): LogAppender {.gcsafe.} =
  result = CustomLogAppender(
    namespace: cla.namespace,
    threshold: cla.threshold,
    doLogMessage: cla.doLogMessage)

#[
method initThreadCopy*(fla: FileLogAppender): LogAppender {.gcsafe.} =
  result = FileLogAppender(
    namespace: fla.namespace,
    threshold: fla.threshold,
    formatter: fla.formatter,
    file: fla.file)
]#


func initLogger(svc: LogService, cfg: LoggerConfig): Logger =
  result = Logger(name: cfg.name, threshold: cfg.threshold, svc: svc)


proc copyAppenders[T](s: seq[T]): seq[T] {.gcsafe.} =
  for app in s:
    result.add(initThreadCopy(app))


proc reloadThreadState*(ls: LogService) {.gcsafe.} =
  ## Refresh this thread's copy of the log service configuration. Note that
  ## this currently loses any loggers defined on this thread since it was last
  ## reloaded.
  acquire(ls.lock)
  # TODO: push loggers defined on this thread to the shared state?
  threadState.cfg = ls.cfg
  threadState.cfg.appenders = copyAppenders(ls.cfg.appenders)
  release(ls.lock)

  let loggers = threadState.cfg.loggers --> map(initLogger(ls, it))
  threadState.loggers = newTable(loggers --> map((it.name, it)))


proc getThreadState(ls: LogService): ThreadState =
  if threadState.loggers.isNil: reloadThreadState(ls)
  return threadState


func fmtLevel(lvl: Level): string {.gcsafe.} =
  case lvl
  of lvlDebug: return "DEBUG"
  of lvlInfo: return "INFO"
  of lvlNotice: return "NOTICE"
  of lvlWarn: return "WARN"
  of lvlError: return "ERROR"
  of lvlFatal: return "FATAL"
  else: return "UNKNOWN"


func `%`*(msg: LogMessage): JsonNode =
  result = %*{
    "scope": msg.scope,
    "level": fmtLevel(msg.level),
    "msg": msg.message,
    "ts": msg.timestamp.formatIso8601
  }

  if msg.error.isSome:
    result["err"] = %($msg.error.get.name & ": " & msg.error.get.msg)
    result["stacktrace"] = %($msg.error.get.trace)

  if msg.additionalData.kind == JObject:
    for (k, v) in pairs(msg.additionalData):
      if not result.hasKey(k): result[k] = v


proc initLogService*(rootLevel = lvlAll): LogService =
  result = cast[LogService](allocShared0(sizeof(LogServiceObj)))
  result.cfg.rootLevel = rootLevel


proc setRootLevel*(ls: LogService, lvl: Level) =
  ls.cfg.rootLevel = lvl


func formatJsonStructuredLog*(msg: LogMessage): string {.gcsafe.} = return $(%msg)


func initConsoleLogAppender*(
    namespace = "",
    threshold = lvlAll,
    formatter = formatJsonStructuredLog,
    useStderr = false): ConsoleLogAppender {.gcsafe.} =
  result = ConsoleLogAppender(
    namespace: namespace,
    threshold: threshold,
    formatter: formatter,
    useStderr: useStdErr)


func initCustomLogAppender*(
    namespace = "",
    threshold = lvlAll,
    doLogMessage: proc (msg: LogMessage) {.gcsafe.}): CustomLogAppender {.gcsafe.} =
  result = CustomLogAppender(
    namespace: namespace,
    threshold: threshold,
    doLogMessage: doLogMessage)


method appendLogMessage*(appender: LogAppender, msg: LogMessage): void {.base, gcsafe.} =
  raise newException(CatchableError, "missing concrete implementation")


method appendLogMessage*(cla: ConsoleLogAppender, msg: LogMessage): void {.gcsafe.} =
  if msg.level < cla.threshold: return

  let strMsg = formatJsonStructuredLog(msg)
  if cla.useStderr:
    stderr.writeLine(strMsg)
    stderr.flushFile()
  else:
    stdout.writeLine(strMsg)
    stdout.flushFile()


method appendLogMessage*(cla: CustomLogAppender, msg: LogMessage): void {.gcsafe.} =
  if msg.level < cla.threshold: return

  cla.doLogMessage(msg)


proc getLogger*(
    ls: LogService,
    name: string,
    threshold = none[Level]()): Logger {.gcsafe.} =

  let ts = getThreadState(ls)
  if not ts.loggers.contains(name):
    ts.loggers[name] = Logger(name: name, threshold: threshold, svc: ls)
  return ts.loggers[name]


proc getLogger*(
    ls: Option[LogService],
    name: string,
    threshold = none[Level]()): Option[Logger] {.gcsafe.} =

  if ls.isNone: return none[Logger]()
  else: return some(getLogger(ls.get, name, threshold))


proc setThreshold*(ls: LogService, name: string, threshold: Level) {.gcsafe.} =
  ## Set the logging threshold for a logger and reload the thread state. This
  ## will affect the logger's thread-local copy, so you don't need to call
  ## `reloadThreadState` to make the change effective for the current thread,
  ## but in a multi-threaded context other pre-existing threads will not see
  ## the change until they reload their state.
  acquire(ls.lock)
  var idx = -1
  for i in 0 ..< ls.cfg.loggers.len:
    if ls.cfg.loggers[i].name == name:
      idx = i
      break
  if idx == -1:
    ls.cfg.loggers.add(LoggerConfig(name: name, threshold: some(threshold)))
  else:
    ls.cfg.loggers[idx].threshold = some(threshold)
  release(ls.lock)
  reloadThreadState(ls)


proc addAppender*(ls: LogService, appender: LogAppender) {.gcsafe.} =
  ## Add a log appender to the log service. This will affect the logger's
  ## thread-local copy, so you don't need to call `reloadThreadState` to make
  ## the change effective for the current thread, but in a multi-threaded
  ## context other pre-existing threads will not see the change until they
  ## reload their state.
  acquire(ls.lock)
  ls.cfg.appenders.add(appender)
  release(ls.lock)
  reloadThreadState(ls)


proc clearAppenders*(ls: LogService) {.gcsafe.} =
  ## Clear all log appenders from the log service. This will affect the
  ## logger's thread-local copy, so you don't need to call `reloadThreadState`
  ## to make the change effective for the current thread, but in a multi-threaded
  ## context other pre-existing threads will not see the change until they
  ## reload their state.
  acquire(ls.lock)
  ls.cfg.appenders = @[]
  release(ls.lock)
  reloadThreadState(ls)


func `<`(a, b: LoggerConfig): bool = a.name < b.name


func getEffectiveLevel(ts: ThreadState, name: string): Level {.gcsafe.} =
  ## Get the effective logging level for a logger. This is the most specific
  ## level that is set for the logger or any of its parents. The root logger
  ## is used as the default if no other level is set.
  result = ts.cfg.rootLevel

  var namespaces = toSeq(values(ts.loggers))
  namespaces = sorted(
    namespaces --> filter(name.startsWith(it.name)),
    SortOrder.Descending)

  for n in namespaces:
    if n.threshold.isSome:
      result = n.threshold.get

proc doLog(logger: Logger, msg: LogMessage): void {.gcsafe.} =
  let ts = getThreadState(logger.svc)
  let threshold =
    if logger.threshold.isSome: logger.threshold.get
    else: getEffectiveLevel(ts, logger.name)

  if msg.level < threshold: return

  for app in ts.cfg.appenders:
    if logger.name.startsWith(app.namespace):
      appendLogMessage(app, msg)


proc log*(l: Logger, lvl: Level, msg: string) {.gcsafe.} =
  l.doLog(LogMessage(
    scope: l.name,
    level: lvl,
    error: none[ref Exception](),
    timestamp: now(),
    message: msg,
    additionalData: newJNull()))


proc log*(
    l: Logger,
    lvl: Level,
    error: ref Exception,
    msg: string ) {.gcsafe.} =
  l.doLog(LogMessage(
    scope: l.name,
    level: lvl,
    error: some(error),
    timestamp: now(),
    message: msg,
    additionalData: newJNull()))

proc log*(l: Logger, lvl: Level, msg: JsonNode) {.gcsafe.} =
  l.doLog(LogMessage(
    scope: l.name,
    level: lvl,
    error: none[ref Exception](),
    timestamp: now(),
    message:
      if msg.hasKey("msg"): msg["msg"].getStr
      else: "",
    additionalData: msg))


proc log*(l: Option[Logger], lvl: Level, msg: string) {.gcsafe.} =
  if l.isSome: log(l.get, lvl, msg)

proc log*(l: Option[Logger], lvl: Level, msg: JsonNode) {.gcsafe.} =
  if l.isSome: log(l.get, lvl, msg)

proc log*(l: Option[Logger], lvl: Level, error: ref Exception, msg: string) {.gcsafe.} =
  if l.isSome: log(l.get, lvl, error, msg)

template debug*[T](l: Logger, msg: T) = log(l, lvlDebug, msg)
template info*[T](l: Logger, msg: T) = log(l, lvlInfo, msg)
template notice*[T](l: Logger, msg: T) = log(l, lvlNotice, msg)
template warn*[T](l: Logger, msg: T) = log(l, lvlWarn, msg)

template error*[T](l: Logger, msg: T) = log(l, lvlError, msg)
template error*(l: Logger, error: ref Exception, msg: string) =
  log(l, lvlError, error, msg)

template fatal*[T](l: Logger, msg: T) = log(l, lvlFatal, msg)
template fatal*(l: Logger, error: ref Exception, msg: string) =
  log(l, lvlFatal, error, msg)

template debug*[T](l: Option[Logger], msg: T) = log(l, lvlDebug, msg)
template info*[T](l: Option[Logger], msg: T) = log(l, lvlInfo, msg)
template notice*[T](l: Option[Logger], msg: T) = log(l, lvlNotice, msg)
template warn*[T](l: Option[Logger], msg: T) = log(l, lvlWarn, msg)

template error*[T](l: Option[Logger], msg: T) = log(l, lvlError, msg)
template error*(l: Option[Logger], error: ref Exception, msg: string) =
  log(l, lvlError, error, msg)

template fatal*[T](l: Option[Logger], msg: T) = log(l, lvlFatal, msg)
template fatal*(l: Option[Logger], error: ref Exception, msg: string) =
  log(l, lvlFatal, error, msg)
