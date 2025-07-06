# Namespaced Logging for Nim

`namespaced_logging` provides a high-performance, thread-safe logging framework
similar to [std/logging][std-logging] with support for namespace-scoped logging
similar to [log4j][] or [logback][] for Nim. It has four main motivating
features:
- Hierarchical, namespaced logging
- Safe and straightforward to use in multi-threaded applications.
- Native support for structured logging.
- Simple, autoconfigured usage pattern mirroring the [std/logging][std-logging]
  interface.

## Getting Started

Install the package from nimble:

```bash
nimble install namespaced_logging
```

## Usage Patterns

### Simple, Autoconfigured Setup
```nim
import namespaced_logging/autoconfigured

# Zero configuration of the LogService required, appender/logger configuration
# is immediately available
addLogAppender(initConsoleLogAppender())
info("Application started")

# Set global threshold
setRootLoggingThreshold(lvlWarn)

# Namespaced loggers, thresholds, and appenders supported
addLogAppender(initFileLogAppender(
  filePath = "/var/log/app_db.log",
  formatter = formatJsonStructuredLog, # provided in namespaced_logging
  namespace = "app/db",
  threshold = lvlInfo))

# in DB code
let dbLogger = getLogger("app/db/queryplanner")
dbLogger.debug("Beginning query plan...")

# native support for structured logs (import std/json)
dbLogger.debug(%*{
  "method": "parseParams",
  "message": "unrecognized param type",
  "invalidType": $params[idx].type,
  "metadata": %(params.meta)
} )
```

### Manual Configuration
```nim
import namespaced_logging

# Manually creating a LogService. This is an independent logging root fully
# isolated from subsequent LogServices initialized
var ls = initLogService()

# Configure logging
ls.addAppender(initConsoleLogAppender())
ls.addAppender(initFileLogAppender("app.log"))
ls.setThreshold("api", lvlWarn)

# Create loggers
let localLogSvc = threadLocalRef(ls)
let apiLogger = localLogSvc.getLogger("api")
let dbLogger = localLogSvc.getLogger("db")
```

### Autoconfigured Multithreaded Application
```nim
import namespaced_logging/autoconfigured
import mummy, mummy/routers

# Main thread setup
addLogAppender(initConsoleLogAppender())

proc createApiRouter*(apiCtx: ProbatemApiContext): Router =
  # This will run on a separate thread, but the thread creation is managed by
  # mummy, not us. Log functions still operate correctly and respect the
  # configuration setup on the main thread
  let logger = getLogger("api")
  logger.trace(%*{ "method_entered": "createApiRouter" })

  # API route setup...

  logger.debug(%*{ "method": "createApiRouter", "routes": numRoutes })


let server = newServer(createApiRouter(), workerThreads = 4)
info("Serving MyApp v1.0.0 on port 8080")

setThreshold("api", lvlTrace) # will be picked up by loggers on worker threads
```


### Manual Multithreaded Application
```nim
import namespaced_logging

# Main thread setup
var logService = initLogService()
logService.addAppender(initConsoleLogAppender())

var localLogSvc = threadLocalRef(logService) # for use on main thread

# Worker thread function
proc worker(ls: LogService) {.thread.} =
  let localLogSvc = threadLocalRef(ls)
  let logger = localLogSvc.getLogger("worker")

  # Runtime configuration changes
  localLogSvc.setThreshold("worker", lvlDebug)
  logger.debug("Worker configured")

# Safe thread creation
createThread(workerThread, worker, logService)
```

### Dynamic Configuration
```nim
# Configuration can change at runtime
proc configureLogging(localLogSvc: ThreadLocalLogService, verbose: bool) =
  if verbose:
    localLogSvc.setRootThreshold(lvlDebug)
    localLogSvc.addAppender(initFileLogAppender("debug.log"))
  else:
    localLogSvc.setRootThreshold(lvlInfo)

# Changes automatically propagate to all threads
```

## Loggers and Appenders

The logging system is composed of two main components: loggers and appenders.
Loggers are used to create log events, which are then passed to the appenders.
Appenders take log events and write them to some destination, such as the
console, a file, or a network socket. Appenders also have a logging level
threshold, which determines which log events are acted upon by the appender,
and, optionally, a namespace filter, which determines from which loggers the
appender accepts log events.

### Heirarchical Logging Namespaces

Loggers are organized hierarchically, with the hierarchy defined by the logger
scope. A logger with the scope `app/service/example` is conceptually a child of
the logger with the scope `app/service`. By default, appenders accept log
events from all loggers, but this can be restricted by setting a namespace
filter on the appender. An appender with a namespace set will accept log events
from all loggers with scopes that start with the namespace. For example, an
appender with the namespace `app` will accept log events from the loggers
`app`, `app/service`, and `app/service/example`, but not from `api/service`.

The other impact of the logger heirarchy is in the effective logging level of
the logger. An explicit logging level threshold can be set for any scope. Any
scope that does not have an explicit inherits its threshold from ancestor
loggers upwards in the scope naming heirarchy. This pattern is explained in
detail in the [logback documentation][effective logging level] and applies in
the same manner to loggers in this library.

### LogMessageFormater

Both the [ConsoleLogAppender](#ConsoleLogAppender) and
[FileLogAppender](#FileLogAppender) can be given a *LogMessageFormatter* to
determine how a log message is formatted before being written.

```nim
type LogMessageFormatter* = proc (msg: LogMessage): string {.gcsafe.}
```

## Available Appenders

### ConsoleLogAppender

Used for writing logs to stdout or stderr.

```nim
proc initConsoleLogAppender*(
    formatter = formatSimpleTextLog,
      ## formatJsonStructuredLog is another useful formatter provided
      ## or you can write your own
    useStderr = false,  ## stdout is used by default
    namespace = "",     ## appender matches all scopes by default
    threshold = lvlAll  ## and accepts all message levels by default
  ): ConsoleLogAppender {.gcsafe.}
```

The first time a message is sent to any *ConsoleLogAppender*, we create a
writer thread which writes messages to the specified output in the order they
are received, flushing the file handle after each write to enforce an ordering.
The ConsoleLogAppender implementation uses a channel to send messages to the
writer thread.

### FileLogAppender

Used for writing logs to files.

```nim
proc initFileLogAppender*(
    filePath: string,
    formatter = formatSimpleTextLog,
      ## formatJsonStructuredLog is another useful formatter provided
      ## or you can write your own
    namespace = "",
    threshold = lvlAll
  ): FileLogAppender {.gcsafe.}

```

Similar to the *ConsoleLogAppender* implementation, the first time a message is
sent to any *FileLogAppender* we create a writer thread which writes messages
to files associated with the *FileLogAppender* configured for the current
*LogService*.

`namespaced_logging` does not currently have built-in logic for file
rotation, but it does play nice with external file rotation strategies. We do
not hold open file handles. The *FileLogAppender* attempts to batch messages
by destination file, opens the file with fmAppend, writes the current batch of
log messages, and then closes the file handle. Because of this, it has no
problem if another process moves or truncates any of the target log files.

### CustomLogAppender

Provides an extension point for custom logging implementations.

```nim
func initCustomLogAppender*[T](
    state: T,   # arbitrary state needed for the appender
    doLogMessage: CustomLogAppenderFunc[T],
      # custom log appender implementation
    namespace = "",
    threshold = lvlAll): CustomLogAppender[T] {.gcsafe.} =
```

The `state` field allows you to explicitly pass in any data that is required
for the custom functionality.

*TODO: rethink this. I chose this to avoid GC-safety issues copying closures
across threads, but maybe I don't need this separate, explicit state field.*

> [!IMPORTANT] The `state` data type must support copy semantics on assignment.
> It is possible to pass a `ref` to `state` and/or data structures that include
> `ref`s, but **you must guarantee they remain valid**, either by allocating
> shared memeory, or (preferably) keeping alive a reference to them that the GC
> is aware of, either on the thread where they were initialized or by
> explicitly telling the GC about the cross-thread reference *(TODO: how?)*.

See [testutil][] and the unit tests in [namespaced\_logging][nsl-unit-tests]
for an example.


## Notes on Use in Multi-Threaded Applications

The loggers and appenders in this library are thread-safe and are intended to
behave more intuitively in a multi-threaded environment than
[std/logging][std-logging] while presenting a similar API. This is particularly
true in environments where the logging setup code may be separated from the
thread-management code (in an HTTP server, for example).

As described in the [Getting Started](#getting-started) section, you can use
the `namespaced_logging/autoconfigured` import to use a simplified interface
that more closely matches the contract of [std/logging][std-logging]. In this
case all thread and state management is done for you. The only limitation is
that you cannot create multiple global *LogService* instances. In practice this
is an uncommon need.

If you do need or want the flexibility to manage the state yourself, import
`namespaced_logging` directly. In this case, the thread which initialized
*LogService* must also be the longest-living thread that uses that *LogService*
instance. If the initializing thread terminates or the *LogService* object in
that thread goes out of scope while other threads are still running and using
the *LogService*, the global state may be harvested by the garbage collector,
leading to use-after-free errors when other threads attempt to log (likely
causing segfaults).

When managing the state yourself, the *LogService* object is the main entry
point for the logging system and should be initialized on the main thread. The
*LogService* contains a reference to the "source of truth" for logging
configuration and is safe to be shared between all threads.

Individual threads should use the *threadLocalRef* proc to obtain a
*ThreadLocalLogService* reference that can be used to create *Logger* objects.
*ThreadLocalLogService* objects cache the global *LogService* state locally to
avoid expensive locks on the shared state. Instead an atomic configuration
version number is maintained to allow the thread-local state to detect global
configuration changes via an inexpensive [load][atomic-load] call and
automatically synchronize only when necessary.

This thread-local caching mechanism is the primary advantage of this logging
system over std/logging in a multi-threaded environment as it means that
the logging system itself is responsible for making sure appenders are
configured for every thread where loggers are used, even if the thread
initialization context is separated from the logging setup code.


## Architectural Design

### Overview

The namespaced logging library is built around a thread-safe architecture that
attempts to balance performance, safety, and usability in multithreaded
environments. The design centers on two key types (*LogService* and
*ThreadLocalLogService*) that work together to provide both thread-safe
configuration management and efficient logging operations.

### Core Architecture Components

#### GlobalLogService (Internal)

At the heart of the system is the `GlobalLogService`, a heap-allocated object
that serves as the single source of truth for logging configuration. This
internal type is not exposed to library users but manages:

- **Shared configuration state**: Appenders, thresholds, and root logging level
- **Synchronization primitives**: Locks and atomic variables for thread
  coordination
- **Background I/O threads**: Dedicated writer threads for console and file
  output
- **Configuration versioning**: Atomic version numbers for efficient change
  detection

The `GlobalLogService` ensures that configuration changes are safely propagated
across all threads while maintaining high performance for logging operations.

#### LogService vs ThreadLocalLogService

The library exposes two distinct types for different usage patterns:

##### LogService (Value Type)
```nim
type LogService* = object
  configVersion: int
  global: GlobalLogService
  appenders: seq[LogAppender]
  thresholds: TableRef[string, Level]
```

The *LogService* object is intended to support uses cases such as:
- **Main thread initialization**: a mutable *LogService* supports all of the
  configuration functions you would typically need when initializing logging
  for an application on the main thread.
- **Cross-thread communication**: Being an `object` type, *LogService* follows
  value semantics and can be safely copied between threads.
- **Service composition**: independently initialized *LogService* objects are
  truly independent and multiple can be created and embedded in larger
  application contexts.

> [!TIP]
> The *LogService* object is the object that is intended to be shared across
> threads.

##### ThreadLocalLogService (Reference Type)
```nim
type ThreadLocalLogService* = ref LogService
```

The *ThreadLocalLogService* is a reference to a thread-local copy of a
*LogService* and can be obtained via *threadLocalRef*. We purposefully use
reference semantics within the context of a thread so that *Logger* objects
created within the same thread context share the same *ThreadLocalLogService*
reference, avoiding the need to synchronize every *Logger* individually.

The *ThreadLocalLogService* is the object that users are expected to interact
with during regular operation and support both the configuration functions of
*LogService* and the creation of *Logger* objects.

> [!CAUTION]
> *ThreadLocalLogService* objects should **never** be shared outside the
> context of the thread in which they were initialized.

### Thread Safety Model

#### Safe Cross-Thread Pattern
```nim
# Main thread setup
let logService = initLogService()
logService.addAppender(initConsoleLogAppender())

# Safe: value semantics allow crossing thread boundaries
proc workerThread(ls: LogService) {.thread.} =
  # Convert to thread-local reference for efficient operations
  let tlls = threadLocalRef(ls)
  let logger = tlls.getLogger("worker")
  logger.info("Worker thread started")

createThread(worker, workerThread, logService)
```

#### Unsafe Pattern (Avoided by Design)
```nim
# DON'T DO THIS - unsafe reference sharing
# ThreadLocalLogService should not be shared across threads
let tlls = threadLocalRef(initLogService())
createThread(worker, someProc, tlls)  # ❌ Potential GC issues
```

### Configuration Synchronization

#### Atomic Version Checking

The library uses atomic version numbers to efficiently detect configuration
changes:

```nim
proc ensureFreshness*(ls: var LogService) =
  # Cheap atomic check first
  if ls.configVersion == ls.global.configVersion.load():
    return  # No changes, return immediately

  # Only acquire lock and copy if versions differ
  withLock ls.global.lock:
    ls.configVersion = ls.global.configVersion.load
    # Sync state...
```

This design ensures that:
- **Hot path is fast**: Most logging operations skip expensive synchronization
- **Changes propagate automatically**: All threads see configuration updates
- **Minimal lock contention**: Locks only acquired when configuration changes

#### Thread-Local Caching

Each thread maintains its own copy of the logging configuration:

- **Appenders**: Thread-local copies created via `clone()` method
- **Thresholds**: Complete copy of namespace-to-level mappings
- **Version tracking**: Local version number for change detection

This caching strategy provides:
- **High performance**: No locks needed for normal logging operations
- **Consistency**: All threads eventually see the same configuration
- **Isolation**: Thread-local state prevents cross-thread interference

## Error Handling

### Overview

For errors that occur during logging operations, there is a callback-based
error handling system designed to attempt to gracefully handle such failures.
Since logging is typically a non-critical operation we prioritize application
stability over guaranteed log delivery.

### Error Handler

The library uses a callback-based error handling pattern where applications can
register custom error handlers to be notified when logging operations fail. The
error handler receives:
- `error`: The exception that caused the failure
- `msg`: A descriptive message providing context about where the error occurred

```nim
type ErrorHandlerFunc* = proc(error: ref Exception, msg: string) {.gcsafe, nimcall.}
```

### Default Error Handler

namespaced\_logging uses the `defaultErrorHandlerFunc` if a custom error
handler has not been configured. The default handler:

1. Attempts to write to stderr, assuming it is likely to be available and monitored
2. Writes an error message and includes both the exception message and stack
   trace (not available in release mode).
3. Fails silently if it is unable to write to to stderr.

### Configuration

#### Setting Custom Error Handlers
```nim
# During initialization
var logService = initLogService(errorHandler = myCustomErrorHandler)

# Or at runtime on either the LogService...
logService.setErrorHandler(myCustomErrorHandler)

# ... or on a ThreadLocalLogService
var localLogSvc = threadLocalRef(logService)
localLogSvc.setErrorHandler(myCustomErrorHandler)
```

#### Disabling Error Reporting
```nim
proc silentErrorHandler(err: ref Exception, msg: string) {.gcsafe, nimcall.} =
  discard # Do nothing

logService.setErrorHandler(silentErrorHandler)
```

### Best Practices

#### Provide Fallbacks
```nim
proc robustErrorHandler(err: ref Exception, msg: string) {.gcsafe, nimcall.} =
  # Primary: Send to monitoring system
  if not sendToMonitoring(err, msg):
    # Secondary: Write to dedicated error log
    if not writeToErrorLog(err, msg):
      # Tertiary: Use stderr as last resort
      try:
        stderr.writeLine("LOGGING ERROR [" & msg & "]: " & err.msg)
        stderr.flushFile()
      except: discard
```

#### Keep Error Handlers Simple

As much as possible, avoid complex operations that might themselves fail.
Don't do heavy operations like database writes, complex network operations, or
file system operations that might fail and cause cascading errors.

[log4j]: https://logging.apache.org/log4j/2.x/
[logback]: https://logback.qos.ch/
[effective logging level]: https://logback.qos.ch/manual/architecture.html#effectiveLevel
[atomic-load]: https://nim-lang.org/docs/atomics.html#load%2CAtomic%5BT%5D%2CMemoryOrder
[std-logging]: https://nim-lang.org/docs/logging.html
[testutil]: /blob/main/src/namespaced_logging/testutil.nim
[nsl-unit-tests]: https://github.com/jdbernard/nim-namespaced-logging/blob/main/src/namespaced_logging.nim#L904
