---
title: Hijack
---

### Hijacking program standard streams

Qiling is able to hijack the program standard streams (_stdin_, _stdout_ and _stderr_) and replace them with custom implementation. The following example shows how to take over stdin and feed it with our own content. That content would be consumed later on by the emulated program.

Simple mock streams may be found at the `pipe` extention package. Though the simple streams would fit most of the common scenarios, they may be easily extended as needed.

```python
from qiling import 
from qiling.extensions import pipe

def force_call_dialog_func(ql: Qiling) -> None:
    # get DialogFunc address
    lpDialogFunc = ql.mem.read_ptr(ql.arch.regs.esp - 0x8, 4)

    # setup stack for DialogFunc
    ql.stack_push(0)
    ql.stack_push(1001)
    ql.stack_push(273)
    ql.stack_push(0)
    ql.stack_push(0x0401018)

    # force EIP to DialogFunc
    ql.arch.regs.eip = lpDialogFunc

if __name__ == "__main__":
    # expected flag: Ea5yR3versing
    ql = Qiling([r'rootfs/x86_windows/bin/Easy_CrackMe.exe'], r'rootfs/x86_windows')

    # hijack program's stdin and feed it with the expected flag
    ql.os.stdin = pipe.SimpleInStream(0)
    ql.os.stdin.write(b'Ea5yR3versing\n')

    ql.hook_address(force_call_dialog_func, 0x00401016)
    ql.run()
```

`stdin` can be substituted with `pipe.InteractiveInStream`, enabling interaction with the running program, similar to the `interactive` feature in [pwntools](https://docs.pwntools.com/en/stable/tubes.html?highlight=interactive#pwnlib.tubes.tube.tube.interactive)

```python
from qiling import Qiling
from qiling.extensions import pipe

if __name__ == "__main__":
    ql = Qiling([r'rootfs/x86_linux/bin/crackme_linux'], r'rootfs/x86_linux')
    ql.os.stdin = pipe.InteractiveInStream() # you will want to type L1NUX when the program waits for input
    ql.run()
```

### Hijacking VFS objects

While the files and folders included within rootfs are all static, the emulated program might need to access virtual file system objects like udev, procfs, sysfs, etc. To bridge that gap Qiling allows binding virtual paths to either existing files on the hosting system, or to custom file objects.

The following example maps the virtual path `/dev/urandom` to the existing `/dev/urandom` file on the hosting system. When the emulated program will access `/dev/random`, the mapped file will be accessed instead.

```python
from qiling import Qiling

if __name__ == "__main__":
    ql = Qiling([r'rootfs/x86_linux/bin/x86_fetch_urandom'], r'rootfs/x86_linux')

    ql.add_fs_mapper(r'/dev/urandom', r'/dev/urandom')
    ql.run()
```

The following example maps the virtual path `/dev/random` to a user-defined file object that allows a finer grained control over the interaction. Note that the mapped object extends `QlFsMappedObject`.

```python
from qiling import Qiling
from qiling.os.mapper import QlFsMappedObject

class FakeUrandom(QlFsMappedObject):

    def read(self, size: int) -> bytes:
        # return a constant value upon reading
        return b"\x04"

    def fstat(self) -> int:
        # return -1 to let syscall fstat ignore it
        return -1

    def close(self) -> int:
        return 0

if __name__ == "__main__":
    ql = Qiling([r'rootfs/x86_linux/bin/x86_fetch_urandom'], r'rootfs/x86_linux')

    ql.add_fs_mapper(r'/dev/urandom', FakeUrandom())
    ql.run()
```

Another usage can be disk emulation. As is often the case, a program would like to access disks directly and you can utilize fs mapper to emulate a disk.

```python
from qiling import Qiling
from qiling.os.disk import QlDisk

if __name__ == "__main__":
    ql = Qiling([r'rootfs/8086_dos/petya/mbr.bin'], r'rootfs/8086_dos')

    # Note that this image is only intended for PoC purposes since the core petya code
    # resides in the sepecific sectors of a hard disk. It doesn't contain any data, either
    # encryted or unencrypted.

    emu_path = 0x80
    emu_disk = QlDisk(r'rootfs/8086_dos/petya/out_1M.raw', emu_path)

    ql.add_fs_mapper(emu_path, emu_disk)
    ql.run()
```

The `QlDisk` object in practice inherits from `QlFsMappedObejct` and implements disk operation logic like cylinder, head, sectors and logic block address. `out_1M.raw` is a raw disk image and `0x80` is the disk drive index in BIOS and DOS. For Linux and Windows, the drive index could be `'/dev/sda'` or `'\\.\PHYSICALDRIVE0'` respectively.

### Hijacking POSIX system calls

POSIX system calls may be hooked to allow the user to modify their parameters, alter the return value or replace their funcionality altogether. System calls may be hooked either by their name or number, and intercepted at one or more stages:
  - `QL_INTERCEPT.CALL`  : when the specified system call is about to be called; may be used to replace the system call functionality altogether
  - `QL_INTERCEPT.ENTER` : before entering the system call; may be used to tamper with the system call parameters values
  - `QL_INTERCEPT.EXIT`  : after exiting the system call; may be used to tamper with the return value

```python
from qiling import Qiling
from qiling.const import QL_INTERCEPT

# customized system calls always use the same arguments list as the original
# ones, but with a Qiling instance on front. The Qiling instance may be used
# to interact with various subsystems, such as the memory or registers
def my_syscall_write(ql: Qiling, fd: int, buf: int, count: int) -> int:
    try:
        # read data from emulated memory
        data = ql.mem.read(buf, count)

        # select the emulated file object that corresponds to the requested
        # file descriptor
        fobj = ql.os.fd[fd]

        # write the data into the file object, if it supports write operations
        if hasattr(fobj, 'write'):
            fobj.write(data)
    except:
        ret = -1
    else:
        ret = count

    ql.log.info(f'my_syscall_write({fd}, {buf:#x}, {count}) = {ret}')

    # return a value to the caller
    return ret

if __name__ == "__main__":
    ql = Qiling([r'rootfs/arm_linux/bin/arm_hello'], r'rootfs/arm_linux')

    # the following call to 'set_syscall' sets 'my_syscall_write' to execute whenever
    # the 'write' system call is about to be called. that practically replaces the
    # existing implementation with the one in 'my_syscall_write'.
    ql.os.set_syscall('write', my_syscall_write, QL_INTERCEPT.CALL)

    # note that system calls may be referred to either by their name or number.
    # an equivalent alternative that replaces the write syscall by refering its number:
    #
    #ql.os.set_syscall(4, my_syscall_write)

    ql.run()
```

### Hijacking OS API (POSIX)

Like system calls, POSIX libc functions may be hooked in a similar fashion, allowing the user to control their functionality.

```python
from qiling import Qiling
from qiling.const import QL_INTERCEPT
from qiling.os.const import STRING

# customized POSIX libc methods accept a single argument that refers to the active
# Qiling instance. The Qiling instance may be used to interact with various subsystems,
# such as the memory or registers. The customized method may or may not return a value
def my_puts(ql: Qiling):
    # Qiling offers a few conviniency methods that abstract away the access to the call
    # parameters. specifying the arguments names and types woud allow Qiling to retrieve
    # their values and parse them accordingly.
    #
    # the following call lists a single argument named 's', whose type is 'STRING'.
    # a dictionary will be created having the key 's' mapped to the null-terminated
    # string read from the memory address pointed by the first argument.
    params = ql.os.resolve_fcall_params({'s': STRING})

    s = params['s']
    ql.log.info(f'my_puts: got "{s}" as an argument')

    # emulate puts functionality
    print(s)

    return len(s)

if __name__ == "__main__":
    ql = Qiling([r'rootfs/x8664_linux/bin/x8664_hello'], r'rootfs/x8664_linux')

    ql.os.set_api('puts', my_puts, QL_INTERCEPT.CALL)
    ql.run()
```

### Hijacking OS API (non POSIX)

The underlying hooking mechanism works differently for non-POSIX operating systems, and allows a simpler approach. API hooks recieve 3 parameters: the associated Qiling instance, the address of the call and a dictionary of parsed paramters - based on the ones specified in the decorator.

- `QL_INTERCEPT.CALL` - hooks intercepting on-call may return a value as necessary
- `QL_INTERCEPT.ENTER` - hooks intercepting on-enter may return a 2-tuple containing an address and a parameters dictionary to override the ones that are passed to the API call
- `QL_INTERCEPT.ENTER` - hooks intercepting on-exit receives an additional integer argument which reflects the return value as it was received from the API call. An alternate return value may be returned to override the one that was received

#### Windows API
Hooks should be decorated with `@winsdkapi`, specifying the calling convention and the paramters list. In case of an empty paramters list, an empty dictionary should be provided. For example, hooking the `memcpy` API:

```python
from qiling import Qiling
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

@winsdkapi(cc=CDECL, params={
    'dest'  : POINTER,
    'src'   : POINTER,
    'count' : UINT
})
def my_memcpy(ql: Qiling, address: int, params):
    dest = params['dest']
    src = params['src']
    count = params['count']

    data = bytes(ql.mem.read(src, count))
    ql.mem.write(dest, data)

    return dest
```
Note: the calling convention argument is effectively ignored on 64-bit and always treated as MS64. This is done to let hooks be compatibility to both 32-bit and 64-bit without having to duplicate them.

#### UEFI API

```python
from qiling import Qiling
from qiling.os.uefi.const import EFI_SUCCESS
from qiling.os.uefi.fncc import *
from qiling.os.uefi.ProcessorBind import *

@dxeapi(params={
    "VariableName" : WSTRING,
    "VendorGuid"   : GUID,
    "Attributes"   : UINT,
    "DataSize"     : UINT,
    "Data"         : POINTER
})
def hook_SetVariable(ql: Qiling, address: int, params):
	data = ql.mem.read(params['Data'], params['DataSize'])
    ql.env[params['VariableName']] = bytes(data)

	return EFI_SUCCESS
```
Note: despite of its name, the `dxeapi` decorator applies to both DXE and SMM API.

Consider the following (incomplete) example showing how `malloc` and `free` may be hooked to detect memory leaks and double-free issues. `malloc` is hooked on-exit so the returned allocation pointer may be collected, while `free` is hooked on-entry to let us inspect the address before it is actually being freed:
```python
chunks = set()

@winsdkapi(cc=CDECL, params={
    'size' : UINT
})
def on_malloc_exit(ql: Qiling, address: int, params, retval: int):
    # collect the address returned by the malloc API
    chunks.add(retval)

    # no need to override return value; do not return anything

@winsdkapi(cc=CDECL, params={
    'address': POINTER
})
def on_free_entry(ql: Qiling, address: int, params):
    memaddr = params['address']

    # examine the addresss that is about to be freed
    try:
        chunks.remove(memaddr)
    except KeyError:
        # the address was probably freed already. is this a double-free?
        ql.log.warning(f'free called from {address:#010x} is suspected to double-free {memaddr:#010x}')

        # to avoid a crash, override the address parameter with a 0 to have it ignored
        params['address'] = 0

        # overrides for the actual 'free' call
        return address, params
    else:
        # no overrides, so do not return anything
        pass

# ...
ql.os.set_api("malloc", on_malloc_exit, QL_INTERCEPT.EXIT)
ql.os.set_api("free", on_free_entry, QL_INTERCEPT.ENTER)

# ...
ql.run()

# if all allocated memory was freed, the chunks set should be empty
if chunks:
    ql.log.warning(f'not all allocated memory was freed, suspected memory leak')
```
