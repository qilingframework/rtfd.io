

#### Binary File
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

#### Shellcode
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

