---
title: Getting Started
---

## Initializing a Qiling instance
Emulating a program or shellcode using Qiling requires a Qiling instance. Most of the emulation parameters and operations are controlled via that instance, which is commonly named `ql`. The arguments used to initialize a Qiling instance may differ based on the emulated target.

### Initialization arguments for binary emulation

| Name                     | Type                             | Description |
|--------------------------|----------------------------------|-----|
| `argv`                   | `Sequence[str]`                  | a sequence of command line arguments to emulate |
| `rootfs`                 | `str`                            | the emulated filesystem root directory. all paths accessed by the emulated program will be based on this directory |
| `env` (optional)         | `MutableMapping[AnyStr, AnyStr]` | a dictionary of environment variables available for the emualted program |

Notes:
 - Qiling will automaticaly infer the target OS and architecture based on the target program
 - Using the hosting system root directory as emulation rootfs is considered a bad practice and it is strictly **not recommended**

### Initialization arguments for shellcode emulation

| Name                     | Type       | Description |
|--------------------------|------------|------------ |
| `code`                   | `bytes`    | shellcode to emulate. that comes instead of `argv` |
| `rootfs` (optional)      | `str`      | _refer to above table_ |
| `ostype`                 | `QL_OS`    | sets target operating system: `LINUX`, `FREEBSD`, `MACOS`, `WINDOWS`, `UEFI`, `DOS`, `QNX`, `MCU`, or `BLOB` |
| `archtype`               | `QL_ARCH`  | sets target architecture: `X86`, `X8664`, `ARM`, `ARM64`, `MIPS`, `A8086`, `CORTEX_M'`, `RISCV`, `RISCV64` or `PPC` |
| `endian` (optional)      | `bool`     | indicates architecture endianess (relevant only to ARM and MIPS) |
| `thumb` (optional)       | `bool`     | indicates ARM thumb mode (relevant only to ARM) |

### Common initialization arguments

| Name                      | Type                    | Description|
|---------------------------|-------------------------|------------|
| `cputype` (optional)      | `QL_CPU`                | sets the underlying CPU model. this is used to make sure certain architectural features are available |
| `verbose` (optional)      | `QL_VERBOSE`            | sets Qiling logging verbosity level (default: `QL_VERBOSE.DEFAULT`). for more details see [print section](https://docs.qiling.io/en/latest/print/) |
| `profile` (optional)      | `str`                   | path to profile file holding additional settings. for more details see [profile section](https://docs.qiling.io/en/latest/profile/) |
| `log_devices` (optional)  | `Collection[IO \| str]` | determines logging output devices: file streams and names are both supported. by default logging output goes to `stderr` |
| `log_override` (optional) | `Logger`                | used to override the default logger with a custom one |
| `log_plain` (optional)    | `bool`                  | indicates whether logger output should be colorful or plain. by default this is determined by the target log device and whether it supports colors |
| `multithread` (optional)  | `bool`                  | indicates whether the target should be emulated as a multi-threaded program |
| `libcache` (optional)     | `bool`                  | indicates whether libraries should be loaded from cache. this saves libraries parsing and relocating time on consequent runs. currently available only for Windows programs |

## Configuring the emulation environment
During its initialization Qiling infers the target OS and architecture, which now may be configured as necessary.

Here are a few common examples:

`ql.add_fs_mapper`  
Used to map a path on the hosting system to a virtual path, so it become available to the emulated program. This can be used in various ways, including mapping objects to emulate 'dynamic' file contents. For example, mapping `/dev/random` to the host's `/dev/zero` to cause the emulated program read only zeros when it reaches the file for a random value:
```python
ql.add_fs_mapper(r'/dev/random', r'/dev/zero')
```

`ql.patch`  
Used to patch a loaded module in memory, either main program or library. This can be used to override code or modify data to allow emulation to get to certain code flows that need to be tested. For example, overriding a certain address with a nop-sled (assuming x86 architecture):
```python
ql.patch(0x401100, b'\x90' * 8)
```

`ql.debugger`  
Set a debugger to be used during the emulation session. For details please refer to the [debugger](https://docs.qiling.io/en/latest/debugger/) page


## Emulation controls
After initializing and configuring Qiling, it is time to start emulation. The emulation starts simply with:
```python
ql.run()
```

Where a finer-grained control is required, use the following optional arguments as needed:
 - `begin` - determine the emulation starting address. this is the address of the first instruction that gets emulated
 - `end` - determine the emulation exit address; the emulation will stop upon reaching that address
 - `timeout` - max emulation time (in microseconds)
 - `count` - max emulation steps; the emulation will stop after emulating that many instructions

Note: Setting a `begin` and `end` addresses is useful when coming to focus the emulation on a specific flow or jump over unnecessary pieces of code (e.g. when fuzzing a specific function). In such case, make sure to manually initialize the necessarey context (e.g. function parameters) beforehand to compensate for the code that used to do that but now is being skipped.

## Examples
A few examples are exhibited in this document and we will illustrate how Qiling Framework works.

### Emulating a binary
```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

if __name__ == "__main__":
    # set up command line argv and emulated os root path
    argv = r'examples/rootfs/netgear_r6220/bin/mini_httpd -d /www -r NETGEAR R6220 -c **.cgi -t 300'.split()
    rootfs = r'examples/rootfs/netgear_r6220'

    # instantiate a Qiling object using above arguments and set emulation verbosity level to DEBUG.
    # additional settings are read from profile file
    ql = Qiling(argv, rootfs, verbose=QL_VERBOSE.DEBUG, profile='netgear.ql')

    # map emulated fs '/proc' dir to the hosting os '/proc' dir
    ql.add_fs_mapper('/proc', '/proc')
  
    # do the magic!
    ql.run()
```

Content of the netgear.ql profile file:
```ini
[MIPS]
mmap_address = 0x7f7ee000
```

### Emulating a shellcode
```python
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

# set up a shellcode to emulate
shellcode = bytes.fromhex('''
   fc4881e4f0ffffffe8d0000000415141505251564831d265488b52603e488b52
   183e488b52203e488b72503e480fb74a4a4d31c94831c0ac3c617c022c2041c1
   c90d4101c1e2ed5241513e488b52203e8b423c4801d03e8b80880000004885c0
   746f4801d0503e8b48183e448b40204901d0e35c48ffc93e418b34884801d64d
   31c94831c0ac41c1c90d4101c138e075f13e4c034c24084539d175d6583e448b
   40244901d0663e418b0c483e448b401c4901d03e418b04884801d0415841585e
   595a41584159415a4883ec204152ffe05841595a3e488b12e949ffffff5d49c7
   c1000000003e488d95fe0000003e4c8d850f0100004831c941ba45835607ffd5
   4831c941baf0b5a256ffd548656c6c6f2c2066726f6d204d534621004d657373
   616765426f7800
''')

# instantiate a Qiling object to emulate the shellcode. when emulating a binary Qiling would be able to automatically
# infer the target architecture and operating system. this, however, is not possible when emulating a shellcode, therefore
# both 'archtype' and 'ostype' arguments must be provided
ql = Qiling(code=shellcode, rootfs=r'examples/rootfs/x8664_windows', archtype=QL_ARCH.X8664, ostype=QL_OS.WINDOWS, verbose=QL_VERBOSE.DEBUG)

# do the magic!
ql.run()
```
