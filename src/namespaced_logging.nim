import logging, sequtils, strutils

export logging.Level

type
  LoggingNamespace* = ref object
    name: string
    level*: Level
    msgPrefix*: string

var knownNamespaces {.threadvar.}: seq[LoggingNamespace]

proc initLoggingNamespace*(name: string, level = lvlInfo, msgPrefix: string): LoggingNamespace =
  result = LoggingNamespace(
    name: name,
    level: level,
    msgPrefix: msgPrefix)

  knownNamespaces.add(result)

proc initLoggingNamespace*(name: string, level = lvlInfo): LoggingNamespace =
  return initLoggingNamespace(name, level, name & ": ")

proc setLevelForNamespace*(namespace: string, lvl: Level) =
  let found = knownNamespaces.filterIt(it.name == namespace)
  for ns in found: ns.level = lvl

proc name*(ns: LoggingNamespace): string = ns.name
proc log*(ns: LoggingNamespace, level: Level, args: varargs[string, `$`]) =
  if level >= ns.level:
    if not ns.msgPrefix.isEmptyOrWhitespace:
      log(level, args.mapIt(ns.msgPrefix & it))
    else: log(level, args)

proc debug*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlDebug, args)
proc info*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlInfo, args)
proc notice*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlNotice, args)
proc warn*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlWarn, args)
proc error*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlError, args)
proc fatal*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlFatal, args)
