# gdbruby.rb

[![Gem Version](https://badge.fury.io/rb/gdbruby.svg)](http://badge.fury.io/rb/gdbruby)

[![Build Status](https://travis-ci.org/gunyarakun/gdbruby.svg?branch=master)](https://travis-ci.org/gunyarakun/gdbruby)

## Overview

gdbruby.rb can output these information with live process or core.

- environment variables
- C stacktrace
- Ruby backtrace

This is Ruby port of gdbperl.pl made by Akira Higuchi.

## Precondition

- Your Ruby executable must have debug symbol.
- on Linux.

## Usage

With live process(process id: 24113)

```sh
$ gdbruby.rb 24113
```

With core file. You have to specify path of ruby executable.

```sh
$ gdbruby.rb core.24113 `rbenv which ruby`
```

You can get core file with gcore script or execute gcore command on gdb like below.

```
$ gdb
(gdb) attach 24113
(gdb) gcore core.24113
(gdb) detach
```

## Options

You can specify options. 0 is interprited as false.

```sh
$ gdbruby.rb 24113 verbose_gdb=1 c_trace=1
```

- verbose_gdb: Show request and response to/from gdb(default: false)
- env: Show environment variables(default: true)
- c\_trace: Show C stacktrace(default:true)

## ToDo

- Print all Ruby threads
- Print arguments on Ruby backtrace
- Speeding up Ruby's type check
- List Ruby objects
- Check memory usage

## FAQ

### Why don't you call functions such like rb\_vm\_get\_sourceline()

If you use gdbruby.rb with live process, gdb can call these functions. But if you use gdbruby.rb with core file, gdb cannot call c functions. So I re-implement these functions.

### Which version does it support?

Ruby 2.0, 2.1 only.
