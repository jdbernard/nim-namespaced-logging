import std/[locks, sequtils, syncio, os, times]
from logging import Level
from ../namespaced_logging import CustomLogAppender, initCustomLogAppender, LogMessage

type
  LoggedMessages* = ref object
    messages*: seq[LogMessage]
    lock: Lock

proc initLoggedMessages*(): LoggedMessages =
  result = LoggedMessages(messages: @[])
  initLock(result.lock)


proc add*(lm: LoggedMessages, msg: LogMessage) =
  withLock lm.lock: lm.messages.add(msg)


proc clear*(lm: LoggedMessages) =
  withLock lm.lock: lm.messages = @[]


proc get*(lm: LoggedMessages): seq[LogMessage] =
  withLock lm.lock: return lm.messages.mapIt(it)


proc testLogAppenderProc(state: LoggedMessages, msg: LogMessage) {.gcsafe, noconv.} =
  state.add(msg)

proc initTestLogAppender*(
    lm: LoggedMessages,
    namespace = "",
    threshold = lvlAll): CustomLogAppender[LoggedMessages] =

  initCustomLogAppender(
    state = lm,
    doLogMessage = testLogAppenderProc,
    namespace = namespace,
    threshold = threshold)


proc waitForFileContent*(
    path: string,
    expectedLines: int,
    timeoutMs: int = 1000): seq[string] =
  let startTime = getTime()
  while (getTime() - startTime).inMilliseconds < timeoutMs:
    if fileExists(path):
      result = readLines(path)
      if result.len >= expectedLines: break
    sleep(10)
