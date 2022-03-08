---
title: Getting Started
---

Few examples are exhibited in this document and we will illustrate how Qiling Framework works

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
from qiling.const import QL_VERBOSE

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
ql = Qiling(code=shellcode, rootfs=r'examples/rootfs/x8664_windows', archtype='x8664', ostype='Windows', verbose=QL_VERBOSE.DEBUG)

# do the magic!
ql.run()
```

### Initialization: ql = Qiling()

How to initialize Qiling

##### Emulating a binary file
In pre-loader (during initialization) state, there are multiple options that can be configured.

Basic Qiling initialization options for **binary** emulation:
| Name                     | Type                             | Description
| :--                      | :--                              | :--
| `argv`                   | `Sequence[str]`                  | a sequence of command line arguments to emulate
| `rootfs`                 | `str`                            | the emulated filesystem root directory. all paths accessed by the emulated program will be based on this directory
| `env` (optional)         | `MutableMapping[AnyStr, AnyStr]` | a dictionary of environment variables available for the emualted program

Basic Qiling initialization options for **shellcode** emulation:
| Name                     | Type                             | Description
| :--                      | :--                              | :--
| `code`                   | `bytes`                          | shellcode to emulate. that comes instead of `argv`
| `rootfs` (optional)      | `str`                            | _refer to above table_                          
| `ostype`                 | `str` or `QL_OS`                 | sets target operating system (case insensitive): `'Linux'`, `'FreeBSD'`, `'MacOS'`, `'Windows'`, `'UEFI'`, `'DOS'`, `'EVM'` or `'QNX'`
| `archtype`               | `str` or `QL_ARCH`               | sets target architecture (case insensitive): `'a8086'`, `'x86'`, `'x8664'`, `'ARM'`, `'ARM64'`, `'MIPS'`, `'EVM'`, `'Cortex_M'`, `'RISCV'` or `'RISCV64'`
| `endian` (optional)      | `bool`                           | indicates architecture endianess (relevant only to ARM and MIPS)
| `thumb` (optional)       | `bool`                           | indicates ARM thumb mode (relevant only to ARM)

Common Qiling initialization options:
| Name                     | Type                             | Description
| :--                      | :--                              | :--
| `verbose` (optional)     | `QL_VERBOSE`                     | sets Qiling logging verbosity level (default: `QL_VERBOSE.DEFAULT`). for more details see [print section](https://docs.qiling.io/en/latest/print/)
| `profile` (optional)     | `str`                            | path to profile file holding additional settings. for more details see [profile section](https://docs.qiling.io/en/latest/profile/)
| `console` (optional)     | `bool`                           | when set to `False`, disables Qiling logging entirely. this is equivalent to setting `verbose=QL_VERBOSE.DISABLED`
| `multithread` (optional) | `bool`                           | indicates whether the target should be emulated as a multi-threaded program
| `libcache` (optional)    | `bool`                           | indicates whether libraries should be loaded from cache. this saves libraries parsing and relocating time on consequent runs. currently available only for Windows

### Setup: after ql=Qiling() and before ql.run()

Available options:

- ql.fs_mapper ("tobe_mapped","actual_path")
> - Map an host file or directory from qiling file or directory to a actual folder eg, ql.fs_mapper('/etc','/real_etc')

- ql.debug_stop = False 
> - Default is false. Stop after missing posix syscall or api
  
- ql.debugger = None 
> - Remote debugger. Please refer to [here](https://docs.qiling.io/en/latest/debugger/)

- ql.verbose = 1
> - from 1 till n, please refer to [print section](https://docs.qiling.io/en/latest/print/) for more details


### Execution: ql.run()
In order to start a binary execution, we just need to call ql.run(). But in certain cases, such as partial execution, there are additional 4 options in ql.run() for more granular control.

```python
ql.run(begin, end, timeout, count)
```

For example,
```python
ql = Qiling()
ql.run(begin = 0xFE, end = 0xFF)
ql.run(begin = 0xAE, end = 0xFF)
```
This will only allow program to execute between 0xFE till 0xFF. So activity like fuzzing does not have to execute the entire file from start till end and only fuzz the targeted sections. Please check out the [sample code](https://docs.qiling.io/en/latest/partial/)
