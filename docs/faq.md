---
title: FAQ
---
### This is an awesome project! Can I donate?
Yes, details please refer to [Cardano Stake Pool](https://www.qiling.io/stake/) or [SWAG](https://www.qiling.io/swag/)

### How to swtich to dev branch
```
git clone https://github.com/qilingframework/qiling.git
git checkout dev
```

### How to run MBR, MS-DOS COM and MS-DOS EXE
Preset arch and os or filename extensions must be as follows

- filename.DOS_EXE

- filename.DOS_COM

- filename.DOS_MBR


### How to install the latest dev branch with pip3
```
pip3 install --user https://github.com/qilingframework/qiling/archive/dev.zip
```

### My program crashes. It says Syscall/API not implemented
- Most likely the syscall or OS API required by the binary is not implemented. You might want to write the syscall or OS api and contribute to the project. But in some cases, the syscall (maybe only syscall) is not being mapped to the arch. Map the syscall to the arch will always work.
- Some cases like [issue 281](https://github.com/qilingframework/qiling/issues/281) we can reuse similar syscall. For example, vfork and fork can be shared most of the time. Always remember, Qiling is a emulator, some of the syscall do not have to be 100% identical to a real kernel.

### Windows API often comes with functionsA and functionW. Do I need to implement both?
- Thanks to [jhumble](https://github.com/jhumble), he implemented wraps from functools to make A and W combile, please refer to [pull request 261](https://github.com/qilingframework/qiling/pull/261).

```python
# HANDLE CreateMutexW(
#   LPSECURITY_ATTRIBUTES lpMutexAttributes,
#   BOOL                  bInitialOwner,
#   LPCWSTR               lpName
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_CreateMutexW(ql, address, params):
    try:
        _type, name = params["lpName"].split("\\")
    except ValueError:
        name = params["lpName"]
        _type = ""

    owning = params["bInitialOwner"]
    handle = ql.os.handle_manager.search(name)
    if handle is not None:
        # ql.os.last_error = ERROR_ALREADY_EXISTS
        return 0
    else:
        mutex = Mutex(name, _type)
        if owning:
            mutex.lock()
        handle = Handle(obj=mutex, name=name)
        ql.os.handle_manager.append(handle)

    return handle.id

# HANDLE OpenMutexA(
#   DWORD   dwDesiredAccess,
#   BOOL    bInheritHandle,
#   LPCSTR lpName
# );
@winsdkapi(cc=STDCALL, dllname=dllname)
def hook_OpenMutexA(ql, address, params):
    return hook_OpenMutexW.__wrapped__(ql, address, params)
```

### UC_ERR_FETCH_UNMAPPED, UC_ERR_WRITE_UNMAPPED and related issues
This is not a "bug". There are several possibilities why these errors occur.

1. Windows API or syscall not being implemented
> - Qiling Framework tries to emulate various platforms such as Linux, MacOS, Windows, FreeBSD and UEFI. All these platforms come with different archnitecture. Its not possible for Qiling Framework to be able to emulate all these syscall/API. Community help is needed.

2. Some specific requiremments are needed.
> - Firmware might need interface br0 and a users testing enviroment might not have it. In this case, ql.patch will come in handy.

3. Required files are missing.
> - Missing conifig file or library can cause the targeted binary fail to run properly.

It is adviseble to always turn on debugging or disassambly mode to pintpoint the issue and try to resolve it. Technically, this is not a bug but rather a feature.

### I tried to connect qiling using gdb, but gdb say: Remote replied unexpectedly to 'vMustReplyEmpty": timeout
This is not a "bug", just some scripts running too slow so gdb is waiting timeout. 

- Input `set remotetimeout 100` in gdb and try to connect again will fix this usually. 

- if not, input `set debug remote 1` and connect again, then send us the debug info as an issue please.

### Syscall not implemented or AttributeError: 'NoneType' object has no attribute 'cur_thread' error
This is not a "bug". By default ql.multithread = False in order to turn on multithread. You need to add ql.multithread = True or with --multithread if you are using qltool.

### I tried to run example scripts but prompted with "file not found" error.
As an effort to streamline Qiling Framework code base, rootfs directory is now hosted separately in its own [repo](https://github.com/qilingframework/rootfs). You can download it by clone the repo. ```cd examples; git clone https://github.com/qilingframework/rootfs.git```

