import logging, sequtils

type
  LoggingNamespace* = ref object
    name: string
    level*: Level
    prependNamespace*: bool

proc initLoggingNamespace*(
    name: string,
    level = lvlInfo,
    prependNamespace = true
  ): LoggingNamespace =

  return LoggingNamespace(
    name: name,
    level: level,
    prependNamespace: prependNamespace)

proc log*(ns: LoggingNamespace, level: Level, args: varargs[string, `$`]) =
  if level >= ns.level:
    if ns.prependNamespace: log(level, args.mapIt(ns.name & it))

proc debug*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlDebug, args)
proc info*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlInfo, args)
proc notice*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlNotice, args)
proc warn*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlWarn, args)
proc error*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlError, args)
proc fatal*(ns: LoggingNamespace, args: varargs[string, `$`]) = log(ns, lvlFatal, args)
