import std/[json, options]
from logging import Level
import ../namespaced_logging

export
  # Types
  Level,
  Logger,
  LogAppender,
  LogMessage,
  ConsoleLogAppender,
  CustomLogAppender,
  CustomLogAppenderFunction,
  FileLogAppender,

  # Procs/Funcs
  `%`,
  initConsoleLogAppender,
  initCustomLogAppender,
  initFileLogAppender,
  formatJsonStructuredLog

var globalLogServiceRef: ThreadLocalLogService = new(LogService)
globalLogServiceRef[] = initLogService()

var threadLocalLogServiceRef {.threadvar.}: ThreadLocalLogService
var defaultLogger {.threadvar.}: Option[Logger]


proc getThreadLocalLogServiceRef(): ThreadLocalLogService {.inline.} =
  if threadLocalLogServiceRef.isNil:
    threadLocalLogServiceRef = new(LogService)
    threadLocalLogServiceRef[] = globalLogServiceRef[]

  return threadLocalLogServiceRef

proc getDefaultLogger(): Logger {.inline.} =

  if defaultLogger.isNone:
    defaultLogger = some(getThreadLocalLogServiceRef().getLogger(""))

  return defaultLogger.get


proc useForAutoconfiguredLogging*(ls: LogService) =
  globalLogServiceRef[] = ls


proc setRootLoggingThreshold*(lvl: Level) =
  setRootThreshold(getThreadLocalLogServiceRef(), lvl)


proc setLoggingThreshold*(scope: string, lvl: Level) =
  setThreshold(getThreadLocalLogServiceRef(), scope, lvl)


proc addLogAppender*(appender: LogAppender) =
  addAppender(getThreadLocalLogServiceRef(), appender)


proc getLogger*(scope: string, lvl: Option[Level] = none[Level]()): Logger =
  getLogger(getThreadLocalLogServiceRef(), scope, lvl)


proc log*(lvl: Level, msg: string) = getDefaultLogger().log(lvl, msg)
proc log*(lvl: Level, msg: JsonNode) = getDefaultLogger().log(lvl, msg)

proc log*(lvl: Level, error: ref Exception, msg: string) =
  getDefaultLogger().log(lvl, error, msg)

template debug*[T](msg: T) = log(lvlDebug, msg)
template info*[T](msg: T) = log(lvlInfo, msg)
template notice*[T](msg: T) = log(lvlNotice, msg)
template warn*[T](msg: T) = log(lvlWarn, msg)
template error*[T](msg: T) = log(lvlError, msg)
template error*(error: ref Exception, msg: string) = log(lvlError, error, msg)
template fatal*[T](msg: T) = log(lvlFatal, msg)
template fatal*(error: ref Exception, msg: string) = log(lvlFatal, error, msg)

when isMainModule:
  import std/unittest
  import ./testutil

  suite "Autoconfigured Logging":
    setup:
      globalLogServiceRef[] = initLogService()
      let loggedMessages = initLoggedMessages()
      let testAppender = initTestLogAppender(loggedMessages)

    test "simple no-config logging":
      addLogAppender(testAppender)
      info("test message")

      let lm = loggedMessages.get()
      check:
        lm.len == 1
        lm[0].level == lvlInfo
        lm[0].message == "test message"
