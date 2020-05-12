---
title: Usage
---

Few examples provided and we will explain each and everypart of Qiling Framework

### Execute a fie
```
import sys
from qiling import *

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output="debug", profile = 'netgear.ql', log_dir='qlog')
    ql.add_fs_mapper('/proc', '/proc')
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/netgear_r6220/bin/mini_httpd","-d","/www","-r","NETGEAR R6220","-c","**.cgi","-t","300"], "rootfs/netgear_r6220")
```

content of netgear.ql
```
[MIPS]
mmap_address = 0x7f7ee000
```

### Execute a shellcode
```
import sys

from binascii import unhexlify
from qiling import *

X8664_WIN = unhexlify(
    'fc4881e4f0ffffffe8d0000000415141505251564831d265488b52603e488b52183e488b52203e488b72503e480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed5241513e488b52203e8b423c4801d03e8b80880000004885c0746f4801d0503e8b48183e448b40204901d0e35c48ffc93e418b34884801d64d31c94831c0ac41c1c90d4101c138e075f13e4c034c24084539d175d6583e448b40244901d0663e418b0c483e448b401c4901d03e418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a3e488b12e949ffffff5d49c7c1000000003e488d95fe0000003e4c8d850f0100004831c941ba45835607ffd54831c941baf0b5a256ffd548656c6c6f2c2066726f6d204d534621004d657373616765426f7800'
)


ql = Qiling(shellcoder=X8664_WIN, archtype="x86", ostype="windows", rootfs="../examples/rootfs/x86_windows", output="default")
ql.run()
```

### Initialization: ql=Qiling()

How to initialiize Qiling

##### Binary file: ql = Qiling()
In pre-loader(during initialization) state, there are multiple options that can be configured.

available:

* filename=None 
> - binary file and argv in [] format, example ["filename","-argv1","argv2"]
- rootfs=None
> virtual "/" folder, this is a "jail" file system when executing Qiling
- env=None
  + always in {}, example {"SHELL":"/bin/bash","HOME":"/tmp"}
- output=None
  + output = ["default", "debug", "disasm", "dump"] and dump=(disam + debug)  
- verbose=1
  + from 1 till n, please refer to [print section](https://docs.qiling.io/en/latest/print/) for more details
- profile=None
  + please refer to [profile section](https://docs.qiling.io/en/latest/profile/) for more details
- log_dir=None 
  + send print out to a log file
- log_split=None 
  + split log, only use it with multithreading
- append=None 
  + append a string to standard log directory or filename
- console=True 
  + print out to console or not. console = False means no print out
- libcache=False
- stdin=0
- stdout=0
- stderr=0


##### Shellcode: ql = Qiling()
In pre-loader(during initialization) state, there are multiple options that can be configured.

available:

- shellcoder=None
  + shellcode in binary mode
- rootfs=None
 + refer to above section, but not compulsory in shellcode  
- env=None
  + refer to above section
- ostype=None
  + "linux", "macos", "windows", "uefi", "freebsd"
- archtype=None
  + "x8664", "x86", "arm", "arm64", "mips"
- bigendian=False
  + Default is false, only availble for "arm" and "mips" for now
- output=None
  + refer to above section
- verbose=1
  + refer to above section
- profile=None
  + refer to above section
- log_dir=None
  + refer to above section
- console=True
  + refer to above section
- stdin=0,
- stdout=0,
- stderr=0,

### Setup: after ql=Qiling() and before ql.run()
All the options can be changed during setup
- ql.fs_mapper = [] 
  + Map a actual file or directory to rootfs. eg, ql.fs_mapper('/etc','/etc')

- ql.debug_stop = False 
  + Default is false. Stop after missing posix syscall or api
  
- ql.debugger = None 
  + Remote debugger. Please refer to [here](https://docs.qiling.io/en/latest/debugger/)

- ql.multithread = False
  + Default is false. Due to the instablity of multithreading, added a swtich for multithreading

- ql.ipv6 = False
  + Default is false. Use IPv6 or not, to avoid binary double bind. ipv6 and ipv4 bind the same port at the same time

- ql.bindtolocalhost = True
  + Bind to localhost

- ql.root = False
  + by turning this on, you must run your analysis with sudo


### Execution: ql.run()
Inorder to start execution. we just need to call ql.run(). But in certain cases, such as partial execution there are addition 4 option in ql.run()

```
ql.run(begin, end, timeout, count)
```

For example,
```
ql = Qiling()
ql.run(begin = 0xFE, end = 0xFF)
ql.run(begin = 0xAE, end = 0xFF)
```
This will only allow program to execute between 0xFE till 0xFF. So activity like fuzzing dont have to execute the entire file from start till end. Only fuzz the targeted sections.