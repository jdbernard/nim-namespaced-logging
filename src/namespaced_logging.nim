import std/[algorithm, atomics, json, locks, options, os, paths, sequtils,
            strutils, tables, times]
import timeutils
import std/logging as stdlog

from std/logging import Level
export Level

type
  GlobalLogServiceObj {.acyclic.} = object
    configVersion: Atomic[int]  # To signal the need for threads to update
    initialized: Atomic[bool]   # To protect deconstruction
    lock: Lock                  # To protect reads/writes across threads

    appenders: seq[LogAppender]
    thresholds: TableRef[string, Level]
    rootLevel: Atomic[Level]

    console: ThreadedConsoleLoggingState
    file: ThreadedFileLoggingState

    errorHandler: ErrorHandlerFunc
    errorHandlerLock: Lock

    takeOverGls: Option[GlobalLogService]
      # Used to direct ThreadLocalLogServices that they should switch to a new
      # GlobalLogService (logging root). This is used primarily in the context of
      # autoconfigured logging where we want to be able to reconfigure the GLS
      # used for autologging, have existing ThreadLocalLogServices switch over
      # to the newly provided GLS, and let the old GLS get garbage-collected

  GlobalLogService = ref GlobalLogServiceObj


  ErrorHandlerFunc* =
    proc (error: ref Exception, msg: string) {.gcsafe,nimcall.}


  LogService* = object
    ## Thread-local logging state intended for use by library consumers
    configVersion: int        # Version of the global state we have
    global: GlobalLogService  # Reference to the global state

    appenders: seq[LogAppender] # Thread-local copy of appenders
    thresholds: TableRef[string, Level]


  ThreadLocalLogService* = ref LogService


  Logger* = ref object
    scope*: string
    threadSvc: ThreadLocalLogService


  LogAppender* = ref object of RootObj
    ## Base type for log appenders. Note that all LogAppenders must (and do)
    ## have a clone method that makes a thread-safe copy of the appender state
    ## that is used when adding appenders to the global service state as well
    ## as during individual thread state refresh.

    namespace*: string
      ## Allows filtering of messages based on their scope.  Messages are
      ## accepted if the Appender's namespace is prefix (or equal to) the
      ## message's scope. For example:
      ##
      ## - ns: `"api"`, scope: `"api/user"` --> processed
      ## - ns: `"api"`, scope: `"db/user"`  --> ignored

    threshold*: Level
      ## Allows filtering based on message level. Appenders will process all
      ## messages whose levels are greater or equal to the appender's
      ## threshold.


  LogMessage* = object
    scope*: string
    level*: Level
    error*: Option[ref Exception]
    timestamp*: DateTime
    message*: string
    additionalData*: JsonNode


  LogMessageFormatter* = proc (msg: LogMessage): string {.gcsafe.}

  ConsoleMessage = object
    message: string
    useStderr: bool


  FileMessage = object
    message: string
    absPath: Path


  ThreadedConsoleLoggingState = object
    initialized: Atomic[bool]
    shutdown: Atomic[bool]
    chan: Channel[ConsoleMessage]
    writerThread: Thread[GlobalLogService]


  ThreadedFileLoggingState = object
    initialized: Atomic[bool]
    shutdown: Atomic[bool]
    chan: Channel[FileMessage]
    writerThread: Thread[GlobalLogService]


  ConsoleLogAppender* = ref object of LogAppender
    ## Log appender that writes log messages to the console. See
    ## *initConsoleLogAppender* for a convenient way to create instances of
    ## this appender.
    formatter*: LogMessageFormatter
      ## Formatter allows for custom formatting of log messages. The default
      ## formatter uses *formatSimpleTextLog* which just writes the log message.
      ## *formatJsonStructuredLog* is also provided to support writing logs out
      ## as structured JSON.
    useStderr*: bool

  CustomLogAppenderFunc*[T] =
    proc(state: T, msg: LogMessage) {.gcsafe, noconv.}

  CustomLogAppender*[T] = ref object of LogAppender
    doLogMessage*: CustomLogAppenderFunc[T]
    state*: T

  FileLogAppender* = ref object of LogAppender
    formatter*: LogMessageFormatter
    absPath*: Path

  StdLoggingAppender* = ref object of LogAppender
    ## Log appender that forwards log messages to the std/logging
    ## implementation. This is primarily intended for libraries and other
    ## situations where you expect that your code will be third-party to others
    ## and want to respect applications which use std/logging for log handlers
    ## and configuration.

    fallbackOnly*: bool
      ## when true, only forward to std/logging where there are no appenders
      ## configured on the related LogService

    formatter*: LogMessageFormatter

const UninitializedConfigVersion = low(int)
let JNULL = newJNull()


proc initLogMessage*(
    scope: string,
    lvl: Level,
    message: string,
    error: Option[ref Exception] = none[ref Exception](),
    additionalData: JsonNode = JNULL): LogMessage =

  LogMessage(
    scope: scope,
    level: lvl,
    error: error,
    timestamp: now(),
    message: message,
    additionalData: additionalData)


proc initLogMessage*(
    scope: string,
    lvl: Level,
    msg: JsonNode,
    error: Option[ref Exception] = none[ref Exception]()): LogMessage =

  LogMessage(
    scope: scope,
    level: lvl,
    error: error,
    timestamp: now(),
    message:
      if msg.hasKey("message"): msg["message"].getStr
      else: "",
    additionalData: msg)


method clone*(app: LogAppender): LogAppender {.base, gcsafe.} =
  raise newException(CatchableError, "missing concrete implementation")


method appendLogMessage(
    appender: LogAppender,
    ls: ThreadLocalLogService,
    msg: LogMessage) {.base, gcsafe.} =
  raise newException(CatchableError, "missing concrete implementation")


proc defaultErrorHandlerFunc*(
    err: ref Exception,
    msg: string) {.gcsafe,nimcall.} =
  try:
    stderr.writeLine("LOGGING ERROR [" & msg & ": " & err.msg)
    stderr.writeLine($err.getStackTrace())
    stderr.flushFile()
  except Exception: discard # we tried...

proc shutdownThreadedConsoleLogging(gls: var GlobalLogServiceObj) =
  if not gls.console.initialized.load(): return

  gls.console.shutdown.store(true) # signal shutdown

  # Send sentinel values to wake up the writer thread
  try: gls.console.chan.send(ConsoleMessage(message: "", useStderr: false))
  except Exception: discard

  joinThread(gls.console.writerThread)
  gls.console.chan.close()
  gls.console.initialized.store(false)


proc shutdownThreadedFileLogging(gls: var GlobalLogServiceObj) =
  if not gls.file.initialized.load(): return

  gls.file.shutdown.store(true) # signal shutdown

  try: gls.file.chan.send(FileMessage(message: "", absPath: Path("/")))
  except Exception: discard

  joinThread(gls.file.writerThread)
  gls.file.chan.close()
  gls.file.initialized.store(false)


proc `=destroy`*(gls: var GlobalLogServiceObj) =
  # only one thread should cleanup
  if not gls.initialized.exchange(false): return

  gls.shutdownThreadedConsoleLogging()
  gls.shutdownThreadedFileLogging()

  try: deinitLock(gls.lock)
  except Exception: discard

  try: deinitLock(gls.errorHandlerLock)
  except Exception: discard


proc ensureFreshness*(ls: var LogService) =
  ## Check our thread-local version of the logging service configuration
  ## against the global log service definition. This uses an atomic version
  ## number to allow the check to be inexpensive, only incurring the more
  ## expensive copy operations if there are actual changes.
  if ls.global.isNil or not ls.global.initialized.load():
    raise newException(ValueError,
      "LogService not properly initialized. Use initLogService to obtain a" &
      "properly initialized LogService object")

  if ls.configVersion == ls.global.configVersion.load(): return

  if ls.global.takeOverGls.isSome:
    let newGls = ls.global.takeOverGls.get
    assert not newGls.isNil
    assert newGls.initialized.load
    ls.global = newGls

  withLock ls.global.lock:
    ls.configVersion = ls.global.configVersion.load

    ls.appenders = @[]
    for a in ls.global.appenders: ls.appenders.add(clone(a))

    ls.thresholds = newTable[string, Level]()
    for ns, t in pairs(ls.global.thresholds): ls.thresholds[ns] = t


proc ensureFreshness*(ls: ThreadLocalLogService) = ensureFreshness(ls[])


proc initGlobalLogService(
    rootLevel = lvlAll,
    errorHandler = defaultErrorHandlerFunc): GlobalLogService =
  result = GlobalLogService()
  result.configVersion.store(0)
  initLock(result.lock)
  initLock(result.errorHandlerLock)

  result.appenders = @[]
  result.thresholds = newTable[string, Level]()
  result.rootLevel.store(rootLevel)
  result.errorHandler = errorHandler

  result.initialized.store(true)

proc initLogService(gls: GlobalLogService): LogService =
  var lsRef: ThreadLocalLogService = ThreadLocalLogService(
    configVersion: UninitializedConfigVersion, global: gls)
  ensureFreshness(lsRef)
  result = lsRef[]


proc initLogService*(
    rootLevel = lvlAll,
    errorHandler = defaultErrorHandlerFunc): LogService =
  ## Initialize a new LogService instance. The resulting LogService object can
  ## be safely copied between threads and provides thread-safe synchronization
  ## of logger configuration and shared state. It is important that the
  ## LogService object returned is retained by the main thread so that garbage
  ## collection does not harvest the global state while it is still in use on
  ## other threads.
  ##
  ## Multiple calls to *initLogService* will result in completely independent
  ## *LogService* objects with their own synchronized coniguration and global
  ## state. This is not expected to be a common usage, but it is supported.
  ## object used to actually configure the log service, attach appenders,
  ## configure thresholds, and create loggers. The ref returned by this
  ## procedure should also be retained by the main thread so that garbage
  ## collection does not harvest the global state while it is still in use.
  let global = initGlobalLogService(rootLevel, errorHandler)
  result = initLogService(global)


proc threadLocalRef*(ls: LogService): ThreadLocalLogService =
  new result
  result[] = ls


proc reportLoggingError(
    gls: GlobalLogService,
    err: ref Exception,
    msg: string) =

  var handler: ErrorHandlerFunc

  withLock gls.errorHandlerLock:
    handler = gls.errorHandler

  if not handler.isNil:
    try: handler(err, msg)
    except:
      # If the error handler itself fails, try the default as a last resort
      try: defaultErrorHandlerFunc(err, msg)
      except Exception: discard # we tried...

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
    "message": msg.message,
    "timestamp": msg.timestamp.formatIso8601
  }

  if msg.error.isSome:
    result["error"] = %($msg.error.get.name & ": " & msg.error.get.msg)
    result["stacktrace"] = %($msg.error.get.trace)

  if msg.additionalData.kind == JObject:
    for (k, v) in pairs(msg.additionalData):
      if not result.hasKey(k): result[k] = v
        # Don't allow overwriting builtin field names


proc setErrorHandler*(
    ls: var LogService,
    errHandler = defaultErrorHandlerFunc) {.gcsafe} =

  if errHandler.isNil: return

  withLock ls.global.errorHandlerLock:
    ls.global.errorHandler = errHandler


proc setErrorHandler*(
    ls: ThreadLocalLogService,
    errHandler = defaultErrorHandlerFunc) {.gcsafe.} =
  setErrorHandler(ls[], errHandler)


proc setRootThreshold*(ls: var LogService, lvl: Level) {.gcsafe.} =
  ls.global.rootLevel.store(lvl)
  ls.global.configVersion.atomicInc


proc setRootThreshold*(ls: ThreadLocalLogService, lvl: Level) {.gcsafe.} =
  setRootThreshold(ls[], lvl)


func formatSimpleTextLog*(msg: LogMessage): string {.gcsafe.} = msg.message


func formatJsonStructuredLog*(msg: LogMessage): string {.gcsafe.} = $(%msg)


proc setThreshold*(ls: var LogService, scope: string, lvl: Level) {.gcsafe.} =
  withLock ls.global.lock:
    ls.global.thresholds[scope] = lvl
    ls.global.configVersion.atomicInc

  ensureFreshness(ls)


proc setThreshold*(ls: ThreadLocalLogService, scope: string, lvl: Level) {.gcsafe.} =
  setThreshold(ls[], scope, lvl)


proc getLogger*(
    ls: ThreadLocalLogService,
    scope: string,
    lvl: Option[Level] = none[Level]()): Logger {.gcsafe.} =
  ## Retrieve a thread-local *Logger* instance. The *lvl* parameter exists as a
  ## convenience to allow you to set the logging level for a logging namespace
  ## and create a logger for it. Passing a value in *lvl*, like:
  ##
  ##     let logger = ls.getLogger('app/api', some(lvlInfo))
  ##
  ## is equivalent to:
  ##
  ##     ls.setThreshold('app/api', lvlInfo)
  ##     let logger = ls.getLogger('app/api')
  ##
  ## **Note:** Logger instances must stay within the context of a single thread.
  ## They are not safe to share across thread boundaries.

  # setThreshold will ensure freshness
  if lvl.isSome: ls.setThreshold(scope, lvl.get)
  else: ensureFreshness(ls)

  result = Logger(scope: scope, threadSvc: ls)


proc addAppender*(ls: var LogService, appender: LogAppender) {.gcsafe.} =
  ## Add a log appender to the global log service and refresh the local thread
  ## state. The updated global state will trigger other threads to refresh
  ## their state as well.
  withLock ls.global.lock:
    var copiedAppender = clone(appender)
    ls.global.appenders.add(copiedAppender)
    ls.global.configVersion.atomicInc

  ensureFreshness(ls)


proc addAppender*(ls: ThreadLocalLogService, appender: LogAppender) {.gcsafe.} =
  addAppender(ls[], appender)


proc clearAppenders*(ls: var LogService) {.gcsafe.} =
  ## Remove all log appenders added to the global log service and refresh the
  ## local thread state. The updated global state will trigger other threads to
  ## refresh their state as well.
  withLock ls.global.lock:
    ls.global.appenders = @[]
    ls.global.configVersion.atomicInc


proc clearAppenders*(ls: ThreadLocalLogService) {.gcsafe.} =
  clearAppenders(ls[])


func getEffectiveThreshold(logger: Logger): Level {.gcsafe.} =
  ## Get the effective logging level threshold for a logger. This is the most
  ## specific level that is set for the logger or any of its parents. The root
  ## logger is used as the default if no other level is set.
  result = logger.threadSvc.global.rootLevel.load

  # Check for exact match first
  if logger.threadSvc.thresholds.hasKey(logger.scope):
    return logger.threadSvc.thresholds[logger.scope]

  # Find all matching namespaces, sorted with the most specific first
  let namespaces =
    toSeq(keys(logger.threadSvc.thresholds))
    .filterIt(logger.scope.startsWith(it))
    .sorted(SortOrder.Descending)

  # If we have matches, return the threshold configured for the most specific.
  if namespaces.len > 0:
    result = logger.threadSvc.thresholds[namespaces[0]]


proc isEnabled*(l: Logger, lvl: Level): bool {.inline,gcsafe.} =
  lvl >= l.getEffectiveThreshold


proc sendToAppenders(logger: Logger, msg: LogMessage) {.gcsafe,inline.} =
  for app in logger.threadSvc.appenders:
    if logger.scope.startsWith(app.namespace) and msg.level >= app.threshold:
      app.appendLogMessage(logger.threadSvc, msg)


template log*(l: Logger, lm: LogMessage) =
  ensureFreshness(l.threadSvc)

  if lm.level >= l.getEffectiveThreshold:
    sendToAppenders(l, lm)

template log*(l: Logger, lvl: Level, msg: untyped) =
  ensureFreshness(l.threadSvc)

  if lvl >= l.getEffectiveThreshold:
    sendToAppenders(l, initLogMessage(l.scope, lvl, msg))


template log*[T: ref Exception](l: Logger, lvl: Level, err: T, msg: untyped) =
  ensureFreshness(l.threadSvc)

  if lvl >= l.getEffectiveThreshold:
    sendToAppenders(
      l,
      initLogMessage(l.scope, lvl, msg, some(cast[ref Exception](err))))

template log*(l: Option[Logger], lm: LogMessage) =
  if l.isSome: log(l.get, lm)

template log*(l: Option[Logger], lvl: Level, msg: untyped) =
  if l.isSome: log(l.get, lvl, msg)

template log*(
    l: Option[Logger],
    lvl: Level,
    error: ref Exception,
    msg: untyped) =
  if l.isSome: log(l.get, lvl, error, msg)

template debug*[L: Logger or Option[Logger], M](l: L, msg: M) =
  log(l, lvlDebug, msg)

template info*[L: Logger or Option[Logger], M](l: L, msg: M) =
  log(l, lvlInfo, msg)

template notice*[L: Logger or Option[Logger], M](l: L, msg: M) =
  log(l, lvlNotice, msg)

template warn*[L: Logger or Option[Logger], M](l: L, msg: M) =
  log(l, lvlWarn, msg)

template error*[L: Logger or Option[Logger], M](l: L, msg: M) =
  log(l, lvlError, msg)

template error*[L: Logger or Option[Logger], M](l: L, error: ref Exception, msg: M) =
  log(l, lvlError, error, msg)

template fatal*[L: Logger or Option[Logger], M](l: L, msg: M) =
  log(l, lvlFatal, msg)

template fatal*[L: Logger or Option[Logger], M](l: L, error: ref Exception, msg: M) =
  log(l, lvlFatal, error, msg)


# -----------------------------------------------------------------------------
# CustomLogAppender Implementation
# -----------------------------------------------------------------------------

func initCustomLogAppender*[T](
    state: T,
    doLogMessage: CustomLogAppenderFunc[T],
    namespace = "",
    threshold = lvlAll): CustomLogAppender[T] {.gcsafe.} =

  if doLogMessage.isNil:
    raise newException(ValueError, "initCustomLogAppender: doLogMessage is nil")

  result = CustomLogAppender[T](
    namespace: namespace,
    threshold: threshold,
    doLogMessage: doLogMessage,
    state: state)

method clone*[T](cla: CustomLogAppender[T]): LogAppender {.gcsafe.} =
  assert not cla.doLogMessage.isNil,
    "CustomLogAppender#clone: source doLogMessage is nil"

  result = CustomLogAppender[T](
    namespace: cla.namespace,
    threshold: cla.threshold,
    doLogMessage: cla.doLogMessage,
    state: cla.state)


method appendLogMessage[T](
    cla: CustomLogAppender[T],
    ls: ThreadLocalLogService,
    msg: LogMessage) {.gcsafe.} =
  try:
    if cla.doLogMessage.isNil:
      raise newException(ValueError, "CustomLogAppender.appendLogMessage: doLogMessage is nil")
    else: cla.doLogMessage(cla.state, msg)
  except Exception:
    ls.global.reportLoggingError(
      getCurrentException(),
      "unable to append to CustomLogAppender")

# -----------------------------------------------------------------------------
# ConsoleLogAppender Implementation
# -----------------------------------------------------------------------------

proc initConsoleLogAppender*(
    formatter = formatSimpleTextLog,
    useStderr = false,
    namespace = "",
    threshold = lvlAll): ConsoleLogAppender {.gcsafe.} =

  result = ConsoleLogAppender(
    namespace: namespace,
    threshold: threshold,
    formatter: formatter,
    useStderr: useStderr)


proc consoleWriterLoop(gls: GlobalLogService) {.thread.} =
  while not gls.console.shutdown.load():
    var didSomething = false

    let (hasData, msg) = gls.console.chan.tryRecv()
    if hasData and msg.message.len > 0:  # Skip empty sentinel messages
      try:
        let output =
          if msg.useStderr: stderr
          else: stdout
        output.write(msg.message)
        output.flushFile()
        didSomething = true
      except IOError:
        discard

    # Small delay if no work to prevent busy waiting
    if not didSomething: sleep(100)


proc initThreadedConsoleLogging(gls: GlobalLogService) =
  if gls.console.initialized.load() or  # don't double-init
     not gls.initialized.load():        # don't init if the gls is shutting down
    return

  withLock gls.lock:
    if gls.console.initialized.load(): return
    gls.console.chan.open()
    gls.console.shutdown.store(false)

    # Create writer thread with reference to the service
    createThread(gls.console.writerThread, consoleWriterLoop, gls)
    gls.console.initialized.store(true)


method clone*(cla: ConsoleLogAppender): LogAppender {.gcsafe.} =
  result = ConsoleLogAppender(
    namespace: cla.namespace,
    threshold: cla.threshold,
    formatter: cla.formatter,
    useStderr: cla.useStderr)


proc appendLogMessageMultiThreaded(
    cla: ConsoleLogAppender,
    ls: ref LogService,
    msg: LogMessage) {.gcsafe.} =

  if not ls.global.console.initialized.load():
    ls.global.initThreadedConsoleLogging()

  try:
    ls.global.console.chan.send(ConsoleMessage(
      message: cla.formatter(msg),
      useStderr: cla.useStderr))
  except Exception:
    try:
      let output =
        if cla.useStderr: stderr
        else: stdout
      output.writeLine(cla.formatter(msg))
      output.writeLine(cla.formatter(LogMessage(
        scope: "namespaced_logging",
        level: lvlError,
        error: some(getCurrentException()),
        timestamp: now(),
        message: "Unable to write log to channel in multi-threaded context."
      )))
      output.flushFile()
    except Exception: discard


proc appendLogMessageSingleThreaded(
    cla: ConsoleLogAppender,
    ls: ref LogService,
    msg: LogMessage) {.gcsafe.} =

  try:
    let output =
      if cla.useStderr: stderr
      else: stdout
    output.writeLine(cla.formatter(msg))
    output.flushFile()
  except Exception: discard


method appendLogMessage(
    cla: ConsoleLogAppender,
    ls: ThreadLocalLogService,
    msg: LogMessage) {.gcsafe.} =
  if msg.level < cla.threshold: return

  try:
    when defined(multithreaded):
      cla.appendLogMessageMultiThreaded(ls, msg)
    else:
      cla.appendLogMessageSingleThreaded(ls, msg)
  except Exception:
    ls.global.reportLoggingError(
      getCurrentException(),
      "unable to append to ConsoleLogAppender")


# -----------------------------------------------------------------------------
# FileLogAppender Implementation
# -----------------------------------------------------------------------------

proc initFileLogAppender*(
    filePath: string,
    formatter = formatSimpleTextLog,
    namespace = "",
    threshold = lvlAll): FileLogAppender {.gcsafe.} =

  result = FileLogAppender(
    namespace: namespace,
    threshold: threshold,
    formatter: formatter,
    absPath: absolutePath(Path(filePath)))

  # TODO: initialize global state for the file log writer


proc fileWriterLoop(gls: GlobalLogService) {.thread.} =
  const bufLen = 128
  var msgsByPath = newTable[Path, seq[FileMessage]]()

  while not gls.file.shutdown.load():
    var didSomething = false

    var msgBuf: array[bufLen, FileMessage]
    var recvIdx = 0
    var writeIdx = 0
    var dataAvailable = true

    while dataAvailable and recvIdx < bufLen:
      # Fill our message buffer if we can
      (dataAvailable, msgBuf[recvIdx]) = gls.file.chan.tryRecv()
      if dataAvailable: inc recvIdx

    # Organize messages by destination file
    msgsByPath.clear()
    while writeIdx < recvIdx:
      let msg = msgBuf[writeIdx]
      inc writeIdx

      if msg.message.len > 0:  # skip empty sentinel messages
        if not msgsByPath.contains(msg.absPath): msgsByPath[msg.absPath] = @[]
        msgsByPath[msg.absPath].add(msg)
        didSomething = true

    # Write all messages in file order to optimize file open/flush/close
    for path, msgs in pairs(msgsByPath):
      var f: File

      if not open(f, $path, fmAppend):
        # TODO: can we do better than silently failing here?
        continue

      for m in msgs:
        try: writeLine(f, m.message)
        except Exception: discard
      flushFile(f)
      close(f)

    # Wait a bit if we had no work to prevent busy waiting
    if not didSomething: sleep(100)


proc initThreadedFileLogging(gls: GlobalLogService) =
  if gls.file.initialized.load(): return

  withLock gls.lock:
    if gls.file.initialized.load(): return
    gls.file.chan.open()
    gls.file.shutdown.store(false)

    # Create writer thread with reference to the service
    createThread(gls.file.writerThread, fileWriterLoop, gls)
    gls.file.initialized.store(true)


method clone*(fla: FileLogAppender): LogAppender {.gcsafe.} =
  result = FileLogAppender(
    namespace: fla.namespace,
    threshold: fla.threshold,
    formatter: fla.formatter,
    absPath: fla.absPath)


proc appendLogMessageMultiThreaded(
    fla: FileLogAppender,
    ls: ref LogService,
    msg: LogMessage) {.gcsafe.} =

  if not ls.global.file.initialized.load():
    ls.global.initThreadedFileLogging()

  try:
    ls.global.file.chan.send(FileMessage(
      message: fla.formatter(msg),
      absPath: fla.absPath))
  except Exception: discard


proc appendLogMessageSingleThreaded(
    fla: FileLogAppender,
    ls: ref LogService,
    msg: LogMessage) {.gcsafe.} =

  try:
    var f: File
    if not open(f, $fla.absPath, fmAppend): return
    writeLine(f, fla.formatter(msg))
    flushFile(f)
    close(f)
  except Exception: discard

method appendLogMessage(
    fla: FileLogAppender,
    ls: ThreadLocalLogService,
    msg: LogMessage) {.gcsafe.} =
  if msg.level < fla.threshold: return

  try:
    when defined(multithreaded):
      fla.appendLogMessageMultiThreaded(ls, msg)
    else:
      fla.appendLogMessageSingleThreaded(ls, msg)
  except Exception:
    ls.global.reportLoggingError(
      getCurrentException(),
      "unable to append to FileLogAppender")


# -----------------------------------------------------------------------------
# StdLoggingAppender Implementation
# -----------------------------------------------------------------------------

func formatForwardedLog*(lm: LogMessage): string =
  ## Default formatter for the StdLoggingAppender that prepends the logger
  ## scope to the message before formatting the message via
  ## *formatSimpleTextLog*
  "[" & lm.scope & "] " & formatSimpleTextLog(lm)


func initStdLoggingAppender*(
    fallbackOnly = true,
    formatter = formatForwardedLog,
    namespace = "",
    threshold = lvlAll): StdLoggingAppender =

  result = StdLoggingAppender(
    namespace: namespace,
    threshold: threshold,
    fallbackOnly: fallbackOnly,
    formatter: formatter)


method clone*(sla: StdLoggingAppender): LogAppender {.gcsafe.} =
  result = StdLoggingAppender(
    namespace: sla.namespace,
    threshold: sla.threshold,
    fallbackOnly: sla.fallbackOnly,
    formatter: sla.formatter)


method appendLogMessage*(
    sla: StdLoggingAppender,
    ls: ThreadLocalLogService,
    msg: LogMessage) {.gcsafe.} =

  if sla.fallbackOnly and ls.appenders.len > 1: return

  stdlog.log(msg.level, sla.formatter(msg))


# -----------------------------------------------------------------------------
# Autoconfiguration Implementation
# -----------------------------------------------------------------------------

var autoGls = GlobalLogService()
  # we create the global reference so that it is maintained by the thread that
  # first imported this module, but leave it uninitialized until
  # initAutoconfiguredLogService is actually called (when
  # namespaced_logging/autoconfigured is imported)

var autoTlls {.threadvar.}: ThreadLocalLogService
var autoLogger {.threadvar.}: Logger


proc initAutoconfiguredLogService*() =
  ## This exists primarily for namespaced_logging/autoconfigured to call as
  ## part of its setup process. This function needs to live here and be
  ## exported for the autoconfigured module's visibility as many of the internal
  ## fields required to properly manage the autoconfigured LogService are not
  ## exported, to avoid confusion and prevent misuse of the library (from a
  ## thread-safety POV).

  assert not autoGls.isNil

  let oldGls = autoGls
  autoGls = initGlobalLogService()

  if oldGls.initialized.load:
    # If we already have an auto-configured GLS, let's log to the existing GLS
    # that we're replacing it.

    withLock oldGls.lock:
      if autoTlls.isNil:
        # If we somehow have an auto-configured GLS but never instantiated a
        # thread-local LogService, let's do so temporarily.
        autoTlls = new(LogService)
        autoTlls.global = oldGls
        ensureFreshness(autoTlls)

      warn(
        getLogger(autoTlls, "namespaced_logging/autoconfigured"),
        "initializing a new auto-configured logging service, replacing this one")

      oldGls.takeOverGls = some(autoGls)
      oldGls.configVersion.atomicInc

  autoTlls = threadLocalRef(initLogService(autoGls))
  autoLogger = autoTlls.getLogger("")


proc getAutoconfiguredLogService*(): ThreadLocalLogService =
  if autoTlls.isNil:
    if not autoGls.initialized.load():
      initAutoconfiguredLogService()
      assert autoGls.initialized.load()

    autoTlls = threadLocalRef(initLogService(autoGls))

  return autoTlls


proc getAutoconfiguredLogger*(): Logger =
  if autoLogger.isNil:
    autoLogger = getLogger(getAutoconfiguredLogService(), "")

  return autoLogger


proc useForAutoconfiguredLogging*(ls: LogService) =
  # Reconfigure the autoconfigured logging behavior to use the given LogService
  # configuration instead of the existing autoconfigured configuration. This is
  # useful in applications that want to control the behavior of third-party
  # libraries or code that use namespaced_logging/autoconfigured.
  #
  # Libraries and other non-application code are suggested to use
  # namespaced_logging/autoconfigured. The autoconfigured log service has no
  # appenders when it is initialized which means that applications which are
  # unaware of namespaced_logging are unaffected and no logs are generated.

  if ls.global == autoGls:
    # As of Nim 2 `==` on `ref`s performs a referential equality check by
    # default, and we don't overload `==`. Referential equality is what we're
    # after here. If the reference in ls already points to the same place as
    # autoGls, we have nothing to do
    return

  if autoGls.initialized.load:
    # if there is an existing autoGls, let's leave instructions for loggers and
    # LogService instances to move to the newly provided GLS before we change
    # our autoGls reference.
    withLock autoGls.lock:
      autoGls.takeOverGls = some(ls.global)
      autoGls.configVersion.atomicInc

  autoGls = ls.global


proc useForAutoconfiguredLogging*(tlls: ThreadLocalLogService) =
  useForAutoconfiguredLogging(tlls[])


proc resetAutoconfiguredLogging*() =
  ## Reset the auto-configured logging service. In general it is suggested to
  # define a new LogService, configure it, and pass it to
  # *useForAutoconfiguredLogging* instead.  in a way that disconnects it
  #from
  autoGls = GlobalLogService()
  initAutoconfiguredLogService()

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

when isMainModule:

  import std/[files, tempfiles, unittest]
  import ./namespaced_logging/testutil

  suite "GlobalLogService Initialization":

    test "initLogService creates valid service":
      let ls = initLogService()
      check:
        ls.global != nil
        ls.global.initialized.load() == true
        ls.global.configVersion.load() == 0
        ls.global.rootLevel.load() == lvlAll
        ls.configVersion >= 0
        ls.configVersion == ls.global.configVersion.load

    test "initLogService with custom root level":
      let ls = initLogService(lvlInfo)
      check ls.global.rootLevel.load() == lvlInfo

  suite "LogService Configuration":
    setup:
      let ls = threadLocalRef(initLogService())

    test "setRootThreshold updates level":
      ls.setRootThreshold(lvlError)
      check ls.global.rootLevel.load() == lvlError

    test "setThreshold adds namespace threshold":
      ls.setThreshold("api", lvlWarn)
      check ls.thresholds["api"] == lvlWarn

    test "ensureFreshness syncs configuration":
      # Modify global state directly
      withLock ls.global.lock:
        ls.global.thresholds["test"] = lvlError
        ls.global.configVersion.atomicInc()

      # Local state should be out of sync
      check not ls.thresholds.hasKey("test")

      # Ensure freshness should sync
      ls.ensureFreshness()
      check ls.thresholds.hasKey("test")
      check ls.thresholds["test"] == lvlError

    test "ensureFreshness syncs configuration between multiple loggers":
      var ls2 = ls[] # use copy semantics
      ls.setThreshold("api", lvlWarn)

      check:
        ls.configVersion == ls.global.configVersion.load
        ls.configVersion != ls2.configVersion
        ls2.configVersion != ls.global.configVersion.load
        ls.thresholds["api"] == lvlWarn
        ls.global.thresholds["api"] == lvlWarn
        not ls2.thresholds.contains("api")

      ls2.ensureFreshness()

      check:
        ls.configVersion == ls2.configVersion
        ls2.configVersion == ls.global.configVersion.load
        ls2.thresholds["api"] == lvlWarn

    test "ensureFreshness syncs configuration across threads":

      var tA, tB: Thread[LogService]
      var lock: Lock
      var cInitA, cInitB, cInitAll, cUpd: Cond

      initLock(lock)
      initCond(cInitAll)
      initCond(cInitA)
      initCond(cInitB)
      initCond(cUpd)

      proc runA(lsGiven: LogService) {.thread, gcsafe.} =
        var ls = lsGiven
        withLock lock:
          # 1a. Initialize both threads
          cInitA.signal()
          wait(cInitAll, lock)

          # 2a. A updates global config
          ls.setThreshold("api", lvlWarn)
          cUpd.signal()

      proc runB(lsGiven: LogService) {.thread, gcsafe.} =
        var ls = lsGiven
        withLock lock:
          # 1b. Initialize both threads
          cInitB.signal()

          # 3. B does not see the global config changes
          wait(cUpd, lock)
          check not ls.thresholds.contains("api")
          # B updates freshness and sees the change
          ls.ensureFreshness()
          check ls.thresholds["api"] == lvlWarn

      # 1. Initialize both threads
      createThread(tA, runA, ls[])
      withLock lock: wait(cInitA, lock)

      createThread(tB, runB, ls[])
      withLock lock: wait(cInitB, lock)

      cInitAll.broadcast() # finished with initialization

      joinThreads(tA, tB)

    test "configuration version incrementing":
      let initialVersion = ls.global.configVersion.load()

      ls.setRootThreshold(lvlWarn)
      check ls.global.configVersion.load() > initialVersion

      ls.setThreshold("test", lvlError)
      check ls.global.configVersion.load() > initialVersion + 1


  suite "Logger Creation and Usage":
    setup:
      let ls = threadLocalRef(initLogService())
      let loggedMsgs = initLoggedMessages()
      ls.addAppender(initTestLogAppender(loggedMsgs))

    test "getLogger creates logger with correct scope":
      let logger = ls.getLogger("api/users")
      check logger.scope == "api/users"

    test "getLogger with threshold sets namespace level":
      let logger = ls.getLogger("api/users", some(lvlWarn))
      check ls.thresholds["api/users"] == lvlWarn

    test "log methods work":
      let logger = ls.getLogger("test")

      logger.log(lvlDebug, "debug string msg")
      logger.log(lvlInfo, %*{"message": "info json msg"})
      logger.log(lvlNotice, "notice string msg")
      logger.log(lvlError, newException(ValueError, "exception msg"), "error ex. msg")

      let lm = loggedMsgs.get()
      check:
        lm.len == 4
        lm[0].level == lvlDebug
        lm[0].message.contains("debug string msg")
        lm[1].level == lvlInfo
        lm[1].message.contains("info json msg")
        lm[2].level == lvlNotice
        lm[2].message.contains("notice string msg")
        lm[3].level == lvlError
        lm[3].message.contains("error ex. msg")

    test "logger convenience methods work":
      let logger = ls.getLogger("test")

      logger.debug("debug message")
      logger.info("info message")
      logger.notice("notice message")
      logger.warn("warn message")
      logger.error("error message")
      logger.fatal("fatal message")

      let lm = loggedMsgs.get()
      check:
        lm.len == 6
        lm[0].level == lvlDebug
        lm[1].level == lvlInfo
        lm[2].level == lvlNotice
        lm[3].level == lvlWarn
        lm[4].level == lvlError
        lm[5].level == lvlFatal

    test "logger with exception logging":
      let logger = ls.getLogger("test")

      let testException = newException(ValueError, "test error")
      logger.error(testException, "Something went wrong")

      let lm = loggedMsgs.get()
      check:
        lm.len == 1
        lm[0].error.isSome
        lm[0].error.get.msg == "test error"

    test "optional logger methods":

      let logger = some(ls.getLogger("test"))
      let noLogger = none(Logger)

      logger.info("test message")
      noLogger.info("should not appear")

      let lm = loggedMsgs.get()
      check lm.len == 1
      check lm[0].message == "test message"

  suite "Threshold and Filtering":
    setup:
      let ls = threadLocalRef(initLogService())
      let loggedMsgs = initLoggedMessages()
      ls.addAppender(initTestLogAppender(loggedMsgs))

    test "root level filtering":
      ls.setRootThreshold(lvlInfo)
      let logger = ls.getLogger("test")

      logger.debug("should be filtered")
      logger.info("should appear")
      logger.error("should appear")

      let lm = loggedMsgs.get()
      check:
        lm.len == 2
        lm[0].level == lvlInfo
        lm[1].level == lvlError

    test "namespace-specific threshold":
      ls.setThreshold("api", lvlWarn)

      let apiLogger = ls.getLogger("api/users")
      let dbLogger = ls.getLogger("db/users")

      apiLogger.info("api info - should be filtered")
      apiLogger.warn("api warn - should appear")
      dbLogger.info("db info - should appear")

      let lm = loggedMsgs.get()
      check:
        lm.len == 2
        lm[0].scope == "api/users"
        lm[0].level == lvlWarn
        lm[1].scope == "db/users"
        lm[1].level == lvlInfo

    test "most specific threshold wins":
      ls.setThreshold("api", lvlWarn)
      ls.setThreshold("api/users", lvlDebug)

      let userLogger = ls.getLogger("api/users/detail")
      let orderLogger = ls.getLogger("api/orders")

      userLogger.debug("user debug - should appear")
      orderLogger.debug("order debug - should be filtered")

      let lm = loggedMsgs.get()
      check:
        lm.len == 1
        lm[0].scope == "api/users/detail"
        lm[0].level == lvlDebug

    test "message construction is avoided if the message is not logged":

      var expensiveCallCount = 0
      proc expensiveCall(): int =
        inc expensiveCallCount
        return expensiveCallCount

      ls.setThreshold("test", lvlInfo)
      let logger = ls.getLogger("test")

      logger.debug("Expensive call (" & $expensiveCall() & ")")
      logger.info("Expensive call (" & $expensiveCall() & ")")

      let lm = loggedMsgs.get()
      check:
        lm.len == 1
        lm[0].message.contains("Expensive call (1)")
        expensiveCallCount == 1

  suite "Appender Functionality":
    setup:
      let ls = threadLocalRef(initLogService())

    test "appender namespace filtering":
      let apiMsgs = initLoggedMessages()
      let dbMsgs = initLoggedMessages()

      let apiAppender = initTestLogAppender(apiMsgs, "api")
      let dbAppender = initTestLogAppender(dbMsgs, "db")

      ls.addAppender(apiAppender)
      ls.addAppender(dbAppender)

      let apiLogger = ls.getLogger("api/users")
      let dbLogger = ls.getLogger("db/connection")
      let otherLogger = ls.getLogger("other/service")

      apiLogger.info("api message")
      dbLogger.info("db message")
      otherLogger.info("other message")

      check:
        apiMsgs.get().len == 1
        apiMsgs.get()[0].scope == "api/users"
        dbMsgs.get().len == 1
        dbMsgs.get()[0].scope == "db/connection"

    test "appender threshold filtering":
      let loggedMsgs = initLoggedMessages()
      let warnAppender = initTestLogAppender(loggedMsgs, "", lvlWarn)
      ls.addAppender(warnAppender)

      let logger = ls.getLogger("test")
      logger.info("info message")
      logger.warn("warn message")
      logger.error("error message")

      let lm = loggedMsgs.get()
      check:
        lm.len == 2
        lm[0].level == lvlWarn
        lm[1].level == lvlError

  suite "Console Appender Construction":
    setup:
      let ls = threadLocalRef(initLogService())

    test "console appender initialization":
      let consoleAppender = initConsoleLogAppender()
      check consoleAppender.useStderr == false
      check consoleAppender.namespace == ""
      check consoleAppender.threshold == lvlAll

    test "console appender with custom settings":
      let consoleAppender = initConsoleLogAppender(
        useStderr = true,
        namespace = "error",
        threshold = lvlError
      )
      check consoleAppender.useStderr == true
      check consoleAppender.namespace == "error"
      check consoleAppender.threshold == lvlError

    test "console appender clone":
      let original = initConsoleLogAppender(useStderr = true, namespace = "test")
      let cloned = clone(original)

      check cloned of ConsoleLogAppender
      let clonedConsole = ConsoleLogAppender(cloned)
      check clonedConsole.useStderr == true
      check clonedConsole.namespace == "test"

  suite "File Appender":
    setup:
      let ls = threadLocalRef(initLogService())

    test "file appender initialization":
      let fileAppender = initFileLogAppender("tempfile.log")
      check fileAppender.absPath == absolutePath(Path("tempfile.log"))
      check fileAppender.namespace == ""
      check fileAppender.threshold == lvlAll

    test "file appender basic logging":
      let (_, pathStr) = createTempFile("nl_test_", ".tmp.log")
      let fileAppender = initFileLogAppender(pathStr)
      ls.addAppender(fileAppender)

      let logger = ls.getLogger("test")
      logger.info("test message")

      # Wait for file to be written
      let lines = waitForFileContent(pathStr, 1)

      check:
        lines.len == 1
        "test message" in lines[0]

      removeFile(pathStr)

    test "file appender clone":
      let original = initFileLogAppender("tempfile.log", namespace = "test")
      let cloned = clone(original)

      check cloned of FileLogAppender
      let clonedFile = FileLogAppender(cloned)
      check clonedFile.absPath == original.absPath
      check clonedFile.namespace == "test"

  suite "StdLoggingAppender":

    var fileLogger: FileLogger
    var tempFile: File
    var tempFilename: string

    setup:
      let ls = threadLocalRef(initLogService())
      (tempFile, tempFilename) = createTempFile("stdlog_test", ".tmp.log")
      fileLogger = newFileLogger(tempFile, flushThreshold = lvlAll)
      addHandler(fileLogger)

    teardown:
      removeHandler(fileLogger)
      try: close(tempFile)
      except Exception: discard
      removeFile(tempFilename)

    test "forwards to std logging":
      ls.addAppender(initStdLoggingAppender())
      let logger = ls.getLogger("test")

      logger.debug("message at debug")
      logger.info("message at info")
      logger.error("message at error")

      tempFile.flushFile()
      close(tempFile)

      check open(tempFile, tempFilename, fmRead)
      let lines = toSeq(lines(tempFile))
      check:
        lines.len == 3
        lines[0] == "DEBUG [test] message at debug"
        lines[1] == "INFO [test] message at info"
        lines[2] == "ERROR [test] message at error"

    test "fallbackOnly works when on":
      ls.addAppender(initStdLoggingAppender())
      let logger = ls.getLogger("test")

      logger.debug("message at debug")
      logger.info("message at info")
      logger.error("message at error")

      let loggedMsgs = initLoggedMessages()
      ls.addAppender(initTestLogAppender(loggedMsgs))

      logger.notice("message at notice")
      logger.warn("message at warn")
      logger.fatal("message at fatal")

      tempFile.flushFile()
      close(tempFile)

      check open(tempFile, tempFilename, fmRead)
      let lines = toSeq(lines(tempFile))
      let lm = loggedMsgs.get()
      check:
        lines.len == 3
        lines[0] == "DEBUG [test] message at debug"
        lines[1] == "INFO [test] message at info"
        lines[2] == "ERROR [test] message at error"

        lm.len == 3
        lm[0].message.contains("message at notice")
        lm[1].message.contains("message at warn")
        lm[2].message.contains("message at fatal")

    test "fallbackOnly works when off":
      ls.addAppender(initStdLoggingAppender(fallbackOnly = false))
      let logger = ls.getLogger("test")

      logger.debug("message at debug")
      logger.info("message at info")
      logger.error("message at error")

      let loggedMsgs = initLoggedMessages()
      ls.addAppender(initTestLogAppender(loggedMsgs))

      logger.notice("message at notice")
      logger.warn("message at warn")
      logger.fatal("message at fatal")

      tempFile.flushFile()
      close(tempFile)

      check open(tempFile, tempFilename, fmRead)
      let lines = toSeq(lines(tempFile))
      let lm = loggedMsgs.get()
      check:
        lines.len == 6
        lines[0] == "DEBUG [test] message at debug"
        lines[1] == "INFO [test] message at info"
        lines[2] == "ERROR [test] message at error"
        lines[3] == "NOTICE [test] message at notice"
        lines[4] == "WARN [test] message at warn"
        lines[5] == "FATAL [test] message at fatal"

        lm.len == 3
        lm[0].message.contains("message at notice")
        lm[1].message.contains("message at warn")
        lm[2].message.contains("message at fatal")
