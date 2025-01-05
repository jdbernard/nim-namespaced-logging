import std/[json, locks, options, strutils, unittest]
import namespaced_logging, zero_functional


type
  TestLogAppender = ref object of LogAppender
    statePtr: ptr TestLogState

  TestLogState = object
    logs: seq[(string, LogMessage)]
    lock: Lock

var sharedTestLogState: ptr TestLogState

proc initSharedTestLogState() =
  sharedTestLogState = cast[ptr TestLogState](allocShared0(sizeof(TestLogState)))
  sharedTestLogState.logs = @[]

method appendLogMessage*(tla: TestLogAppender, msg: LogMessage): void {.gcsafe.} =
  if msg.level < tla.threshold: return
  acquire(sharedTestLogState.lock)
  sharedTestLogState.logs.add((tla.namespace, msg))
  release(sharedTestLogState.lock)

method initThreadCopy*(tla: TestLogAppender): LogAppender {.gcsafe.} =
  TestLogAppender(
    namespace: tla.namespace,
    threshold: tla.threshold,
    statePtr: tla.statePtr)

proc initTestLogAppender(namespace = "", threshold = lvlAll): TestLogAppender =
  TestLogAppender(
    namespace: namespace,
    threshold: threshold,
    statePtr: sharedTestLogState)

initSharedTestLogState()

suite "initialization":

  test "can create LogService":
    let logSvc = initLogService()
    check:
      not logSvc.isNil

  test "reloadThreadState":
    let logSvc = initLogService()
    reloadThreadState(logSvc)


  test "create Logger":
    let logSvc = initLogService()
    let logger = logSvc.getLogger("test")

    check:
      logger.threshold.isNone
      logger.name == "test"

  test "create Logger with threshold":
    let logSvc = initLogService()
    reloadThreadState(logSvc)

    let logger = logSvc.getLogger("test", some(lvlDebug))

    check:
      logger.threshold.isSome
      logger.threshold.get == lvlDebug
      logger.name == "test"

  test "initConsoleLogAppender":
    let cla = initConsoleLogAppender()

suite "log methods":

  test "log with ConsoleLogAppender":
    let logSvc = initLogService()
    let cla = initConsoleLogAppender(threshold = lvlDebug)
    let tla = initTestLogAppender()
    logSvc.addAppender(cla)
    logSvc.addAppender(tla)
    reloadThreadState(logSvc)

    let logger = logSvc.getLogger("test")
    logger.info("Test log message.")

    acquire(sharedTestLogState.lock)
    check sharedTestLogState.logs.len == 1
    let log = sharedTestLogState.logs[0][1]
    check:
      log.message == "Test log message."
      log.level == lvlInfo
      log.scope == "test"
      log.error.isNone
      log.additionalData.kind == JNull
    sharedTestLogState.logs.setLen(0)
    release(sharedTestLogState.lock)

  test "log with error":
    let logSvc = initLogService()
    let tla = initTestLogAppender()
    logSvc.addAppender(tla)
    reloadThreadState(logSvc)

    let logger = logSvc.getLogger("test")
    logger.error(newException(Exception, "Test error message."), "exception occurred")

    acquire(sharedTestLogState.lock)
    check sharedTestLogState.logs.len == 1
    let log = sharedTestLogState.logs[0][1]
    check:
      log.message == "exception occurred"
      log.level == lvlError
      log.scope == "test"
      log.error.isSome
      log.error.get.name == "Exception"
      log.error.get.msg == "Test error message."
      log.additionalData.kind == JNull
    sharedTestLogState.logs.setLen(0)
    release(sharedTestLogState.lock)

suite "namespaces":

  test "appenders at the root level accept all messages":
    let logSvc = initLogService()
    let tla = initTestLogAppender()
    logSvc.addAppender(tla)
    reloadThreadState(logSvc)

    let l1 = logSvc.getLogger("")
    let l2 = logSvc.getLogger("test")
    let l3 = logSvc.getLogger("test/sub")

    l1.info("message from root")
    l2.info("message from test")
    l3.info("message from test/sub")

    acquire(sharedTestLogState.lock)
    let logs = sharedTestLogState.logs
    check:
      logs.len == 3
      logs[0][1].message == "message from root"
      logs[1][1].message == "message from test"
      logs[2][1].message == "message from test/sub"

    sharedTestLogState.logs.setLen(0)
    release(sharedTestLogState.lock)

  test "appenders accept messages at their namespace":
    let logSvc = initLogService()
    let tla = initTestLogAppender(namespace = "test")
    logSvc.addAppender(tla)
    reloadThreadState(logSvc)

    let logger = logSvc.getLogger("test")
    logger.info("message from test")

    acquire(sharedTestLogState.lock)
    check:
      sharedTestLogState.logs.len == 1
      sharedTestLogState.logs[0][0] == "test"
      sharedTestLogState.logs[0][1].message == "message from test"
    sharedTestLogState.logs.setLen(0)
    release(sharedTestLogState.lock)

  test "appenders accept messages from scopes within their namespace":
    let logSvc = initLogService()
    let tlaRoot = initTestLogAppender(namespace = "")
    let tlaTest = initTestLogAppender(namespace = "test")
    logSvc.addAppender(tlaRoot)
    logSvc.addAppender(tlaTest)
    reloadThreadState(logSvc)

    let logger = logSvc.getLogger("test/sub")
    logger.info("message from test/sub")

    acquire(sharedTestLogState.lock)
    let logs = sharedTestLogState.logs
    check:
      logs.len == 2
      logs[0][0] == ""
      logs[0][1].message == "message from test/sub"
      logs[1][0] == "test"
      logs[1][1].message == "message from test/sub"
    sharedTestLogState.logs.setLen(0)
    release(sharedTestLogState.lock)

  test "appenders do not accept messages outside their namespace":
    let logSvc = initLogService()
    let tlaRoot = initTestLogAppender(namespace = "")
    let tlaTest = initTestLogAppender(namespace = "test")
    logSvc.addAppender(tlaRoot)
    logSvc.addAppender(tlaTest)
    reloadThreadState(logSvc)

    let logger = logSvc.getLogger("other")
    logger.info("message from other")

    acquire(sharedTestLogState.lock)
    let logs = sharedTestLogState.logs
    check:
      logs.len == 1
      logs[0][0] == ""
      logs[0][1].message == "message from other"

    sharedTestLogState.logs.setLen(0)
    release(sharedTestLogState.lock)

suite "thresholds":

  test "logger gates messages by level":
    let logSvc = initLogService()
    let tla = initTestLogAppender()
    logSvc.addAppender(tla)
    reloadThreadState(logSvc)

    let logger = logSvc.getLogger("test", some(lvlInfo))
    logger.debug("message at debug level")
    logger.info("message at info level")
    logger.warn("message at warn level")

    acquire(sharedTestLogState.lock)
    let logs = sharedTestLogState.logs
    check:
      logs.len == 2
      logs[0][1].message == "message at info level"
      logs[1][1].message == "message at warn level"
    sharedTestLogState.logs.setLen(0)
    release(sharedTestLogState.lock)

  test "root threshold applies when logger has none":
    let logSvc = initLogService(lvlWarn)
    let tla = initTestLogAppender()
    logSvc.addAppender(tla)
    reloadThreadState(logSvc)

    let logger = logSvc.getLogger("test")
    logger.debug("message at debug level")
    logger.info("message at info level")
    logger.warn("message at warn level")

    acquire(sharedTestLogState.lock)
    let logs = sharedTestLogState.logs
    check:
      logs.len == 1
      logs[0][1].message == "message at warn level"
    sharedTestLogState.logs.setLen(0)
    release(sharedTestLogState.lock)

  test "logger inherits effective threshold from ancestors":
    let logSvc = initLogService()
    let tla = initTestLogAppender()
    logSvc.addAppender(tla)
    reloadThreadState(logSvc)

    let l1 = logSvc.getLogger("test", some(lvlInfo))
    let l2 = logSvc.getLogger("test/sub")
    let l3 = logSvc.getLogger("test/sub/subsub")
    let l4 = logSvc.getLogger("other")

    l3.debug("message at debug level")
    l3.info("message at info level")
    l3.warn("message at warn level")
    l4.debug("message at debug level")

    acquire(sharedTestLogState.lock)
    let l3Logs = sharedTestLogState.logs --> filter(it[1].scope == "test/sub/subsub")
    let l4Logs = sharedTestLogState.logs --> filter(it[1].scope == "other")
    check:
      l3Logs.len == 2
      l3Logs[0][1].message == "message at info level"
      l3Logs[1][1].message == "message at warn level"
      l4Logs.len == 1
      l4Logs[0][1].message == "message at debug level"
    sharedTestLogState.logs.setLen(0)
    release(sharedTestLogState.lock)

  test "appender gates messages by level":
    let logSvc = initLogService()
    let tlaInfo = initTestLogAppender(namespace="a", threshold = lvlInfo)
    let tlaDebug = initTestLogAppender(namespace="a/b", threshold = lvlDebug)
    logSvc.addAppender(tlaInfo)
    logSvc.addAppender(tlaDebug)
    reloadThreadState(logSvc)

    let logger = logSvc.getLogger("a/b")
    logger.debug("message at debug level")
    logger.info("message at info level")
    logger.warn("message at warn level")

    acquire(sharedTestLogState.lock)
    let aLogs = sharedTestLogState.logs --> filter(it[0] == "a")
    let bLogs = sharedTestLogState.logs --> filter(it[0] == "a/b")
    check:
      aLogs.len == 2
      aLogs[0][1].message == "message at info level"
      aLogs[1][1].message == "message at warn level"
      bLogs.len == 3
      bLogs[0][1].message == "message at debug level"
      bLogs[1][1].message == "message at info level"
      bLogs[2][1].message == "message at warn level"

    sharedTestLogState.logs.setLen(0)
    release(sharedTestLogState.lock)
