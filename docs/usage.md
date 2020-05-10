#### Initialization

##To Run a binary file
```
import sys
from qiling import *

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output="debug")
    ql.root = False
    ql.add_fs_mapper('/proc', '/proc')
    ql.profile('netgear.ql')
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/netgear_r6220/bin/mini_httpd","-d","/www","-r","NETGEAR R6220","-c","**.cgi","-t","300"], "rootfs/netgear_r6220")
```

content of netgear.ql
```
[MIPS]
mmap_address = 0x7f7ee000
log_dir = qlog
log_split = True
```

##To Run a Shellcode
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

### Binary File
In pre-loader(during initialization) state, there are multiple options that can be configured.

available:

```
  filename=None,
  rootfs=None,
  env=None,
  output=None,
  verbose=1,
  profile=None,
  console=True,
  stdin=0,
  stdout=0,
  stderr=0,
```

### Shellcode
In pre-loader(during initialization) state, there are multiple options that can be configured.

available:

```
  shellcoder=None,
  rootfs=None,
  env=None,
  ostype=None,
  archtype=None,
  bigendian=False,
  output=None,
  verbose=1,
  profile=None,
  console=True,
  stdin=0,
  stdout=0,
  stderr=0,
```



required for shellcode execution only:
```
ostype
arch
```

ql.profile settings
```
stack_address = 0xhexaddress
stack_size = 0xhexaddress
interp_address = 0xhexaddress
mmap_address = 0xhexaddress
```

additional options
```
output = ["debug","off","disasm","dump"] // dump=(disam + debug)
console
log_dir = path to all the logs
```
#### Pre-Execution Settings
APIs allow users to instuments an executeable file/shellcode before execution.
```
ql.set_callback
ql.patch
ql.root
ql.debug
ql.set_syscall
ql.set_api
```


#### Qiling's Coding Style
Some tips if you with to sent your pull request to Qiling Framework
```
ql.nprint("")
```
ql.nprint will not print anything when output="off"


```
ql.dprint(D_INFO,"")
```
ql.dprint will only print anything when output="dump" or output="debug"

### 

In pre-loader(during initialization) state, there are multiple options that can be configured.

required:
```
path
rootfs
```

required for shellcode execution only:
```
ostype
arch
```

ql.profile settings
```
stack_address = 0xhexaddress
stack_size = 0xhexaddress
interp_address = 0xhexaddress
mmap_address = 0xhexaddress
```

additional options
```
output = ["debug","off","disasm","dump"] // dump=(disam + debug)
console
log_dir = path to all the logs
```
#### Pre-Execution Settings
APIs allow users to instuments an executeable file/shellcode before execution.
```
ql.set_callback
ql.patch
ql.root
ql.debug
ql.set_syscall
ql.set_api
```


#### Qiling's Coding Style
Some tips if you with to sent your pull request to Qiling Framework
```
ql.nprint("")
```
ql.nprint will not print anything when output="off"


```
ql.dprint(D_INFO,"")
```
ql.dprint will only print anything when output="dump" or output="debug"

### 

