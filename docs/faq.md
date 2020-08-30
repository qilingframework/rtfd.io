---
title: FAQ
---
### This is a awesome project. How can i donate

- To makes things easier, we structure the "price" this way :-
```
  - Below 20 USD - Name on donation page<br>
  - 20 USD - Stickers<br>
  - 60 USD- Stickers + USB Drive<br>
  - 120 USD and above - Stickers + USB Dirve + T-Shirt
```  
- "USD" denotes the US dolar equivalent amount of coin value during the time of donation  
- Please notify us via email to kj@qiling.io after making the donation.
- These are not ready made. So, you might need to wait abit for the goods to be delivered.
- Paypal accepted at our web store

<img src="https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/swag.jpg">
```
- Paypal via Web Store
  - https://www.hardwareninja.store/c/QilingFramework
- XMR
  - 46T1c5taWuP6G4XvAG5shC6a7eai4Qe4HPFj5qEGyJzzMVRa9M9MR4DbNbbSDKtbgNR6bvWyj32Wb3HySYZuDqUp2GCr52o
- DASH
  XhTsLXTQEhN5F7hKtq8HV867um3HZuXvF9
- ADA
  - DdzFFzCqrht8MbmRQL8v86XG5vQHYNC6NQwFkhCW4rsNHMLfzWyxVTce5yFayg6QqJBdL7AapwvFL3fBAoBmPLR9gDbkzLGfVVEGHnNC
- ETH: 
  - 0xec095228411d4a232f4d221ad7defcde36eb981f
- BTC: 
  - 1NmxDWWak8qtpmYGnXBK1osRNNYH2zxpZs
```



### How to swtich to dev branch
```
git clone https://github.com/qilingframework/qiling.git
git checkout dev
```

### My program crashes. It says Syscall/API not implemented
- Most likely the syscall or OS api required by the binary is not implemented. You might want to write the syscall or OS api and contribute to the project. But in some cases, the syscall (maybe only syscall) is not being mapped to the arch. Map the syscall to the arch will always work.
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

2. Some specific requiremment needed.
> - Firmware might need interface br0 and a users testing enviroment might not have it. In this case, ql.patch will come in handy.

3. Required files are missing.
> - Missing conifig file or library can cause the targeted binary fail to run properly.

It is adviseble to always turn on debugging or disassambly mode to pintpoint the issue and try to resolve it. Technically, this is not a bug but rather a feature.

### I try to connect qiling useing gdb, but gdb say: Remote replied unexpectedly to 'vMustReplyEmpty": timeout
This is not a "bug", just some scripts running too slow so gdb is waiting timeout. 
- Input `set remotetimeout 100` in gdb and try to connect again will fix this usually. 
- if not, input `set debug remote 1` and connect again, then send to us the debug info as an issue please.

### Syscall not implemented or AttributeError: 'NoneType' object has no attribute 'cur_thread' error
This is not a "bug". By default ql.multithread = False in order to turn on multithread. You need to add ql.multithread = True or with --multithread if you are using qltool
