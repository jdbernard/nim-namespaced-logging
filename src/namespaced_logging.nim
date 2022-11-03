import std/[logging, options, sequtils, strutils, tables]

export logging

type
  LoggingNamespace* = ref object
    name: string
    level*: Level
    msgPrefix*: string

var knownNamespacesInst {.threadvar.}: TableRef[string, LoggingNamespace]

template knownNamespaces(): TableRef[string, LoggingNamespace] =
  if knownNamespacesInst == nil:
    knownNamespacesInst = newTable[string, LoggingNamespace]()
  knownNamespacesInst

proc initLoggingNamespace(name: string, level = lvlInfo, msgPrefix: string): LoggingNamespace =
  result = LoggingNamespace(
    name: name,
    level: level,
    msgPrefix: msgPrefix)

  knownNamespaces[name] = result

proc getLoggerForNamespace*(
    namespace: string,
    level = lvlInfo,
    msgPrefix: Option[string] = none[string]()
  ): LoggingNamespace =
  ## Get a LogginNamesapce for the given namespace. The first time this is
  ## called for a given name space a new logger will be created. In that case,
  ## the optional `level` and `msgPrefix` will be used to configure the logger.
  ## In all other cases, these paratmers are ignored and the existing namespace
  ## instance is returned

  if knownNamespaces.hasKey(namespace): return knownNamespaces[namespace]
  else:
    if msgPrefix.isSome:
      return initLoggingNamespace(namespace, level, msgPrefix.get)
    else:
      return initLoggingNamespace(namespace, level, namespace)

proc setLevelForNamespace*(namespace: string, lvl: Level, recursive = false) =
  if recursive:
    for k, v in knownNamespaces.pairs:
      if k.startsWith(namespace):
        v.level = lvl
  else: getLoggerForNamespace(namespace).level = lvl

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
