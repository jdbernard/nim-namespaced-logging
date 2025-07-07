import std/[json, options, strutils]
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
  CustomLogAppenderFunc,
  FileLogAppender,

  # Procs/Funcs
  `%`,
  initConsoleLogAppender,
  initCustomLogAppender,
  initFileLogAppender,
  formatJsonStructuredLog,
  useForAutoconfiguredLogging


proc setRootLoggingThreshold*(lvl: Level) =
  setRootThreshold(getAutoconfiguredLogService(), lvl)


proc setLoggingThreshold*(scope: string, lvl: Level) =
  setThreshold(getAutoconfiguredLogService(), scope, lvl)


proc addLogAppender*(appender: LogAppender) =
  addAppender(getAutoconfiguredLogService(), appender)


proc clearLogAppenders*() =
  clearAppenders(getAutoconfiguredLogService())


proc getLogger*(scope: string, lvl: Option[Level] = none[Level]()): Logger =
  getLogger(getAutoconfiguredLogService(), scope, lvl)


template log*(lm: LogMessage) = log(getAutoconfiguredLogger(), lm)

template log*(lvl: Level, msg: untyped) = log(getAutoconfiguredLogger(), lvl, msg)

template log*[T: ref Exception](lvl: Level, error: T, msg: untyped) =
  log(getAutoconfiguredLogger(), lvl, error, msg)

template debug*[T](msg: T) = log(lvlDebug, msg)
template info*[T](msg: T) = log(lvlInfo, msg)
template notice*[T](msg: T) = log(lvlNotice, msg)
template warn*[T](msg: T) = log(lvlWarn, msg)
template error*[T](msg: T) = log(lvlError, msg)
template error*[T](error: ref Exception, msg: T) = log(lvlError, error, msg)
template fatal*[T](msg: T) = log(lvlFatal, msg)
template fatal*[T](error: ref Exception, msg: T) = log(lvlFatal, error, msg)

when isMainModule:
  import std/unittest
  import ./testutil

  suite "Automatic Global Setup":

    setup:
      clearLogAppenders()
      let loggedMsgs = initLoggedMessages()
      addLogAppender(initTestLogAppender(loggedMsgs))
      # note that we are not resetting the global log service reference as the
      # module default behavior in setting up the global log service reference
      # is what we want to test

    test "simple logging works":
      info("test message")

      let lm = loggedMsgs.get()
      check:
        lm.len == 1
        lm[0].level == lvlInfo
        lm[0].message == "test message"
        lm[0].scope == ""

  suite "Autoconfigured Logging":
    setup:
      resetAutoconfiguredLogging()
      let loggedMsgs = initLoggedMessages()
      addLogAppender(initTestLogAppender(loggedMsgs))

    test "message construction is avoided if the message is not logged":
      var expensiveCallCount = 0
      proc expensiveCall(): int =
        inc expensiveCallCount
        return expensiveCallCount

      setRootLoggingThreshold(lvlInfo)

      debug("Expensive call (" & $expensiveCall() & ")")
      info("Expensive call (" & $expensiveCall() & ")")

      let lm = loggedMsgs.get()
      check:
        lm.len == 1
        lm[0].message.contains("Expensive call (1)")
        expensiveCallCount == 1

    test "thread local variables are cached":
      # Get the service reference multiple times - should be same instance
      let svc1 = getAutoconfiguredLogService()
      let svc2 = getAutoconfiguredLogService()
      check svc1 == svc2

      # Default logger should also be cached
      let logger1 = getAutoconfiguredLogger()
      let logger2 = getAutoconfiguredLogger()
      check logger1 == logger2

    test "logging with exceptions works":
      let testException = newException(ValueError, "test error")
      error(testException, "Something went wrong")

      let lm = loggedMsgs.get()
      check:
        lm.len == 1
        lm[0].level == lvlError
        lm[0].error.isSome
        lm[0].error.get.msg == "test error"

    test "all convenience methods work":
      debug("debug message")
      info("info message")
      notice("notice message")
      warn("warn message")
      error("error message")
      fatal("fatal message")

      let lm = loggedMsgs.get()
      check:
        lm.len == 6
        lm[0].level == lvlDebug
        lm[1].level == lvlInfo
        lm[2].level == lvlNotice
        lm[3].level == lvlWarn
        lm[4].level == lvlError
        lm[5].level == lvlFatal

    test "message construction is avoided if the message is not logged":
      var expensiveCallCount = 0
      proc expensiveCall(): int =
        inc expensiveCallCount
        return expensiveCallCount

      setRootLoggingThreshold(lvlInfo)

      debug("Expensive call (" & $expensiveCall() & ")")
      info("Expensive call (" & $expensiveCall() & ")")

      let lm = loggedMsgs.get()
      check:
        lm.len == 1
        lm[0].message.contains("Expensive call (1)")
        expensiveCallCount == 1


  suite "Global Service Management":
    setup:
      resetAutoconfiguredLogging()

    test "useForAutoconfiguredLogging changes global service":

      let origLogs = initLoggedMessages()
      let newLogs = initLoggedMessages()

      # autoconfiged first
      addLogAppender(initTestLogAppender(origLogs))
      let origLogger = getAutoconfiguredLogger()
      debug("msg 1")

      # Then we setup a custom service that will take over the autoconfig
      var customLogService = initLogService(lvlWarn)
      customLogService.addAppender(initTestLogAppender(newLogs))
      useForAutoconfiguredLogging(customLogService)

      # Subsequent calls to debug, info, etc. should use the new config
      debug("msg 2 - should be filtered")
      warn("msg 3 - should appear")

      # Any Loggers that are still around should also get updates
      origLogger.debug("msg 4 - should be filtered")
      origLogger.error("msg 5 - should appear")

      let lmOrig = origLogs.get()
      let lmNew = newLogs.get()
      check:
        lmOrig.len == 1
        lmOrig[0].message == "msg 1"
        lmNew.len == 2
        lmNew[0].message == "msg 3 - should appear"
        lmNew[1].message == "msg 5 - should appear"

    test "configuration changes affect autoconfigured logging":
      let loggedMsgs = initLoggedMessages()
      addLogAppender(initTestLogAppender(loggedMsgs))

      # Initially all levels should work
      debug("debug message")

      # Change root threshold
      setRootLoggingThreshold(lvlInfo)

      # Debug should now be filtered
      debug("should be filtered")
      info("should appear")

      let lm = loggedMsgs.get()
      check:
        lm.len == 2  # First debug + info
        lm[0].level == lvlDebug
        lm[1].level == lvlInfo
