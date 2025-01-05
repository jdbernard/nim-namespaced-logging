# Namespaced Logging for Nim

`namespaced_logging` provides a logging framework similar to [log4j][] or
[logback][] for Nim. It has three main motivating features:
- Hierarchical, namespaced logging
- Safe and straightforward to use in multi-threaded applications.
- Native support for structured logging (old-style string logging is also
  supported).

## Getting Started

Install the package from nimble:

```bash
nimble install namespaced_logging
```

Then, in your application, you can use the logging system like so:

```nim
import namespaced_logging

# On the main thread
let logService = initLogService()
logService.addAppender(initConsoleAppender(LogLevel.INFO))

# On any thread, including the main thread
let logger = logService.getLogger("app/service/example")
logger.info("Log from the example service")

# Only get logs at the WARN or higher level from the database module
let logger = logService.getLogger("app/database", threshold = some(Level.lvlWarn))
logger.error("Database connection failed")
```

## Loggers and Appenders

The logging system is composed of two main components: loggers and appenders.
Loggers are used to create log events, which are then passed to the appenders.
Appenders take log events and write them to some destination, such as the
console, a file, or a network socket. Appenders also have a logging level
threshold, which determines which log events are acted upon by the appender,
and, optionally, a namespace filter, which determines from which loggers the
appender accepts log events.

### Heirarchical Logging and Namespaces

Loggers are organized hierarchically, with the hierarchy defined by the logger
name. A logger with the name `app/service/example` is a child of the logger
with the name `app/service`. By default, appenders accept log events from all
loggers, but this can be restricted by setting a namespace filter on the
appender. An appender with a namespace set will accept log events from all
loggers with names that start with the namespace. For example, an appender with
the namespace `app` will accept log events from the loggers `app`,
`app/service`, and `app/service/example`, but not from `api/service`.

The other impact of the logger heirarchy is in the effective logging level of
the logger. Any logger can have an explicit logging level set, but if it does
not, the effective logging level is inherited from ancestor loggers upwards in
the logger heirarchy. This pattern is explained in detail in the [logback
documentation][effective logging level] and applies in the same manner to
loggers in this library.


## Notes on Use in Multi-Threaded Applications

The loggers and appenders in this library are thread-safe and behaves more
intuitively in a multi-threaded environment than `std/logging`, particularly in
environments where the logging setup code may be separated from the
thread-management code (in an HTTP server, for example).

The *LogService* object is the main entry point for the logging system and
should be initialized on the main thread. The *LogService* contains the "source
of truth" for logging configuration and is shared between all threads.
Internally all access to the *LogService* is protected by a mutex.

Logging can be very noisy and if the *LogService* needed to be consulted for
every log event, it could easily become a performance bottleneck. To avoid
this, the *getLogger* procedure makes a thread-local copy of the logging system
configuration (loggers defined and appenders attached).

**Note** that this means that the thread-local cache of the logging system
configuration can become stale if the logging system configuration is changed
after the thread-local copy is made (if another appender is added, for
example). This is a trade-off to avoid the performance penalty of consulting
the *LogService* for every log event.

This thread-local caching mechanism is the primary advantage of this logging
system over `std/logging` in a multi-threaded environment as it means that
the logging system itself is responsible for making sure appenders are
configured for every thread where loggers are used, even if the thread
initialization context is separated from the logging setup code.

If you find yourself needing to change the logging configuration after the
logging system has been initialized, the *reloadThreadState* procedure can be
used to update the thread-local cache of the logging system configuration, but
it must be called on the thread you wish to update.

As a final note, the advice to initialize the *LogService* on the main thread
is primarily to simplify the configuration of the logging service and avoid the
need to manually reload caches on individual threads. A *LogService* reference
is required to call *getLogger*, but it can be created on any thread.

## Custom Appender Implementations

Due to the thread-safety of the logging system, there are a few additional
considerations when implementing custom appenders. The *LogAppender* abstract
class is the base class for all appenders. To implement a custom appender, two
methods must be implemented:

### `appendLogMessage`

```nim
method appendLogMessage*(appender: CustomLogAppender, msg: LogMessage): void {.base, gcsafe.}
```

This is the primary appender implementation that takes a LogMessage and
writes it to the appender's destination. As the signature suggests, the
implementation must be GC-safe. As a multi-method, the *CustomLogAppender* type
should be replaced by the actual name of your custom appender.

Because the *LogAppender* uses multi-methods for dynamic dispatch, the
custom appender class must also be a `ref` type.

### `initThreadCopy`

```nim
method initThreadCopy*(app: LogAppender): LogAppender {.base, gcsafe.}
```

This method is used to create a thread-local copy of the appender. It is called
by the *reloadThreadState* procedure to update the thread-local cache of the
logging system configuration. The implementation will be passed the appender
instance that was provided to the *addAppender* procedure and must return a
thread-local copy of that appender.

The `initThreadCopy` implementations for the built-in *ConsoleLogAppender* and
*FileLogAppender* provide simple examples of how to implement this method by
simply copying state into the local thread, but this method can also be used
to perform any other thread-specific initialization that may be required for
the appender implementation.

### Example Custom Appender

The following defines a simple custom appender that writes log messages to a
database table. It uses the [waterpark][] connection pooling library to manage
database connections as waterpark is also thread-safe and makes implementation
straight-forward.

```nim
import db_connectors/db_postgres
import namespaced_logging, waterpark, waterpark/db_postgres

type DbLogAppender = ref object of LogAppender
  dbPool: PostgresPool

let dbPool: PostgresPool = newPostgresPool(10, "", "", "", connectionString)

method initThreadCopy*(app: LogAppender): LogAppender =
  result = DbLogAppender(dbPool: dbPool) # copy semantics as PostgresPool is an object

method appendLogMessage*(appender: DbLogAppender, msg: LogMessage): void {gcsafe.} =
  appender.withConnection conn:
    conn.insert(
      "INSERT INTO log_events " &
      "  (level, scope, message, error, timestamp, custom_fields) " &
      "VALUES " &
      "  (?, ?, ?, ?, ?, ?)",
      msg.level,
      msg.scope,
      msg.message,
      if msg.error.isSome: msg.error.msg
      else: "",
      msg.timestamp,
      msg.additionalData)
```



[log4j]: https://logging.apache.org/log4j/2.x/
[logback]: https://logback.qos.ch/
[effective logging level]: https://logback.qos.ch/manual/architecture.html#effectiveLevel
