---
title: Hijack
---

### stdio: stdin, stdout, stderr

- Qiling is able to hijack stdin, stdout, stderr and and replace with custom functions.

```python
from qiling import *

class StringBuffer:
    def __init__(self):
        self.buffer = b''

    def read(self, n):
        ret = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return ret

    def readline(self, end=b'\n'):
        ret = b''
        while True:
            c = self.read(1)
            ret += c
            if c == end:
                break
        return ret

    def write(self, string):
        self.buffer += string
        return len(string)


def force_call_dialog_func(ql):
    # get DialogFunc address
    lpDialogFunc = ql.unpack32(ql.mem.read(ql.reg.esp - 0x8, 4))
    # setup stack for DialogFunc
    ql.stack_push(0)
    ql.stack_push(1001)
    ql.stack_push(273)
    ql.stack_push(0)
    ql.stack_push(0x0401018)
    # force EIP to DialogFunc
    ql.reg.eip = lpDialogFunc


def our_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)
    ql.stdin = StringBuffer()
    ql.stdin.write(b"Ea5yR3versing\n")
    ql.hook_address(force_call_dialog_func, 0x00401016)
    ql.run()


if __name__ == "__main__":
    # Flag is : Ea5yR3versing
    our_sandbox(["rootfs/x86_windows/bin/Easy_CrackMe.exe"], "rootfs/x86_windows")

```

### Hijack objects via fs mapper

Fs mapper works in two ways.

- Hijack the path in emulated environment to the paht on your host machine. e.g. Bind '/dev/urandom' to the real device.

```
from qiling import *

if __name__ == "__main__":
    ql = Qiling(["rootfs/x86_linux/bin/x86_fetch_urandom"], "rootfs/x86_linux")
    ql.add_fs_mapper("/dev/urandom", "/dev/urandom")
    ql.run()
```

- Redirect the read/write operations to a user-defined object.

This is advanced usage for fs mapper. Below is an example which maps '/dev/urandom' to a user-defined implementation. Note all such objects should inherit from `QlFsMappedObject`.

```python
from qiling import *
from qiling.os.mapper import QlFsMappedObject

class Fake_urandom(QlFsMappedObject):

    def read(self, size):
        return b"\x01" # fixed value for reading /dev/urandom

    def fstat(self): # syscall fstat will ignore it if return -1
        return -1

    def close(self):
        return 0

if __name__ == "__main__":
    ql = Qiling(["rootfs/x86_linux/bin/x86_fetch_urandom"], "rootfs/x86_linux")
    ql.add_fs_mapper("/dev/urandom", Fake_urandom())
    ql.run()
```

Another usage can be disk emulation. As is often the case, a program would like to access disks directly and you can utilize fs mapper to emulate a disk.

```python
from qiling import *
from qiling.os.disk import QlDisk
from qiling.const import QL_VERBOSE

if __name__ == "__main__":
    ql = Qiling(["rootfs/8086_dos/petya/mbr.bin"], 
                 "rootfs/8086_dos",
                 console=False, 
                 verbose=QL_VERBOSE.DEBUG, 
                 log_dir=".")
    # Note:
    # This image is only intended for PoC since the core petya code resides in the
    # sepecific sectors of a harddisk. It doesn't contain any data, either encryted
    # or unencrypted.
    ql.add_fs_mapper(0x80, QlDisk("rootfs/8086_dos/petya/out_1M.raw", 0x80))
    ql.run()
```

The `QlDisk` in practice inherits from `QlFsMappedObejct` and implements disk operation logic like cylinder, head, sectors and logic block address. `out_1M.raw` is a raw disk image and `0x80` is the disk drive index in BIOS and DOS. For Linux and Windows, the drive index could be '/dev/sda' or '\\.\PHYSICALDRIVE0'.

### ql.set_syscall()

- Custom syscall handler by syscall name or syscall number.
- Notes: If the syscall function is not be implemented in qiling, qiling does not know which function should be replaced.
- In that case, you must specify syscall by its number.
- To reset, ql.set_syscall("write", None)

```python
from qiling import *
from qiling.const import *

def my_syscall_write(ql, write_fd, write_buf, write_count, *args, **kw):
    regreturn = 0

    try:
        buf = ql.mem.read(write_buf, write_count)
        ql.nprint("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
        ql.os.file_des[write_fd].write(buf)
        regreturn = write_count
    except:
        regreturn = -1
        ql.nprint("\n+++++++++\nmy write(%d,%x,%i) = %d\n+++++++++" % (write_fd, write_buf, write_count, regreturn))
        if ql.verbose >= QL_VERBOSE.DEBUG:
            raise

    ql.os.definesyscall_return(regreturn)


if __name__ == "__main__":
    ql = Qiling(["rootfs/arm_linux/bin/arm_hello"], "rootfs/arm_linux", verbose=QL_VERBOSE.DEBUG)
    ql.set_syscall(0x04, my_syscall_write)
    ql.set_syscall("write", my_syscall_write)
    ql.run()
```

### Posix - ql.set_api()
-  Posix's Libc function replacement
```python
from qiling import *
from qiling.os.const import STRING
from qiling.const import QL_VERBOSE

def my_puts(ql):
    params = ql.os.resolve_fcall_params({'s': STRING})
    print(f'puts("{params["s"]}")')

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
    ql.set_api('puts', my_puts)
    ql.run()
```

### Non Posix - ql.set_api()

- Mostly used in Windows API

```python
from qiling import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.const import *

@winsdkapi(cc=STDCALL, dllname=dllname)
def my_puts(ql, address, params):
    ret = 0
    ql.nprint("\n+++++++++\nmy random Windows API\n+++++++++\n")
    string = params["str"]
    ret = len(string)
    return ret


def my_onenter(ql, address, params):
    print("\n+++++++++\nmy OnEnter")
    print("lpSubKey: %s" % params["lpSubKey"])
    params = ({'hKey': 2147483649, 'lpSubKey': 'Software', 'phkResult': 4294954932})
    print("+++++++++\n")
    return  address, params


def my_onexit(ql, address, params):
    print("\n+++++++++\nmy OnExit")
    print("params: %s" % params)
    print("+++++++++\n")


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG)
    ql.set_api("_cexit", my_onenter, QL_INTERCEPT.ENTER)
    ql.set_api("puts", my_puts)
    ql.set_api("atexit", my_onexit, QL_INTERCEPT.EXIT)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x8664_windows/bin/x8664_hello.exe"], "rootfs/x8664_windows")

```

### On enter interceptor on Posix function with ql.set_api()
- Hijack parameter before Posix function
- Posix's Libc function replacement
```python
from qiling import *
from qiling.const import *
from qiling.os.const import STRING

def my_puts(ql):
    params = ql.os.resolve_fcall_params({'s': STRING})
    print('Hijack Libc puts("{params["s"]}")

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
    ql.set_api('puts', my_puts, QL_INTERCEPT.ENTER)
    ql.run()
```

- However, Windows and UEFI usages are different from posix.

```python
from qiling import *
from qiling.const import *

def my_onenter(ql, address, params):
    print("\n+++++++++\nmy OnEnter")
    print("lpSubKey: %s" % params["lpSubKey"])
    params = ({'hKey': 2147483649, 'lpSubKey': 'Software', 'phkResult': 4294954932})
    print("+++++++++\n")
    return  address, params


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG)
    ql.set_api("_cexit", my_onenter, QL_INTERCEPT.ENTER)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x8664_windows/bin/x8664_hello.exe"], "rootfs/x8664_windows")
```

### On enter interceptor with ql.set_syscall

- Hijack parameter before OS APIs or syscall
- Example below shows replaced parameter of syscall 0x1 with write_onenter
```python
from qiling import *
from qiling.const import *

def write_onenter(ql, arg1, arg2, arg3, *args):
    print("enter write syscall!")
    ql.reg.rsi = arg2 + 1
    ql.reg.rdx = arg3 - 1

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
    ql.set_syscall(1, write_onenter, QL_INTERCEPT.ENTER)
    ql.run()
```

### On exit interceptor with ql.set_syscall()

- Hijack returns value after OS APIs or syscall execution
- Example below shows replaced output result of syscall 0x1 with write_onExit
```python
from qiling import *
from qiling.const import *

def write_onExit(ql, arg1, arg2, arg3, *args):
    print("exit write syscall!")
    ql.reg.rax = arg3 + 1

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
    ql.set_syscall(1, write_onExit, QL_INTERCEPT.EXIT)
    ql.run()
```

### On exit interceptor with ql.set_api()

- However, Windows and UEFI usages are different from posix.
```python
from qiling import *
from qiling.const import *

def my_onexit(ql, address, params):
    ql.nprint("\n+++++++++\nmy OnExit")
    print("params: %s" % params)
    ql.nprint("+++++++++\n")


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG)
    ql.set_api("RegDeleteValueW", my_onexit, QL_INTERCEPT.EXIT)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/RegDemo.exe"], "rootfs/x86_windows")
```

### ql.patch()

- Patching a binary or patching a lib loaded by the binary

```python
ql.patch(0x0000000000000575, b'qiling\x00', file_name = b'libpatch_test.so')
ql.patch(0x0000000000000575, b'qiling\x00')  
```

### ql.compile()

- Backed by keystone engine, compile any code into binary. Mainly for ql.patch()

```python
ql.compile(ASM, ql.archtype)
```
