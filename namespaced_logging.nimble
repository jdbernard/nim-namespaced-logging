# Package

version       = "2.0.1"
author        = "Jonathan Bernard"
description   = "Wrapper around std/logging to provide namespaced logging."
license       = "MIT"
srcDir        = "src"


# Dependencies

requires @["nim >= 2.2.0", "zero_functional"]

# from https://git.jdb-software.com/jdb/nim-packages
requires "timeutils"

task test, "Run unittests for the package.":
  exec "nimble c src/namespaced_logging.nim src/namespaced_logging/autoconfigured.nim"
  exec "src/namespaced_logging.out"
  exec "src/namespaced_logging/autoconfigured"
