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

### Posix - ql.set_api()
-  Posix's Libc function replacement
```python
from qiling import *

def my_puts(ql):
    addr = ql.func_arg[0]
    print("puts(%s)" % ql.mem.string(addr))

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", output="debug")
    ql.set_api('puts', my_puts)
    ql.run()
```

### Non Posix - ql.set_api()

- Mostly used in Windows API

```python
from qiling import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *

@winapi(cc=CDECL, params={
    "str": STRING
})
def my_puts(self, address, params):
    ret = 0
    self.ql.nprint("\n+++++++++\nmy random Windows API\n+++++++++\n")
    string = params["str"]
    ret = len(string)
    return ret


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output = "debug")
    ql.set_syscall("puts", my_puts)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/x86_hello.exe"], "rootfs/x86_windows")

```

### On enter interceptor  with ql.set_api()

- Hijack parameter before OS APIs or syscall
- if the replaced function contains "_onEnter" (not case sensitive), it will be a on enter function.
- Example below shows replace parameter of syscall 0x1 with write_onenter
```python
from qiling import *
from qiling.const import *

def write_onenter(ql, arg1, arg2, arg3, *args):
    print("enter write syscall!")
    ql.reg.rsi = arg2 + 1
    ql.reg.rdx = arg3 - 1

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", output="debug")
    ql.set_syscall(1, write_onenter)
    ql.run()
```

- However, Windows and UEFI usage is different from posix.

```python
from qiling import *

def my_onenter(ql, address, params):
    print("\n+++++++++\nmy OnEnter")
    print("lpSubKey: %s" % params["lpSubKey"])
    params = ({'hKey': 2147483649, 'lpSubKey': 'Software', 'phkResult': 4294954932})
    print("+++++++++\n")
    return  address, params


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output = "debug")
    ql.set_api("_cexit", my_onenter)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x8664_windows/bin/x8664_hello.exe"], "rootfs/x8664_windows")
```


### On exit interceptor with ql.set_api()
- Hijack return value after OS APIs or syscall execution
- if the replaced function contains "_onExit" (not case sensitive), it will be a on exit function.
- Example below shows replace output result of syscall 0x1 with write_onExit
```python
from qiling import *

def write_onExit(ql, arg1, arg2, arg3, *args):
    print("exit write syscall!")
    ql.reg.rax = arg3 + 1

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", output="debug")
    ql.set_syscall(1, write_onExit)
    ql.run()
```

- However, Windows and UEFI usage is different from posix.
```python
from qiling import *

def my_onexit(ql, address, params):
    ql.nprint("\n+++++++++\nmy OnExit")
    print("params: %s" % params)
    ql.nprint("+++++++++\n")


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output = "debug")
    ql.set_api("RegDeleteValueW", my_onexit)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/RegDemo.exe"], "rootfs/x86_windows")
```

### ql.set_syscall()

- Custom syscall handler by syscall name or syscall number.
- Notes: If the syscall function is not be implemented in qiling, qiling does not know which function should be replaced.
- In that case, you must specify syscall by its number.
- To reset, ql.set_syscall("write", None)

```python
from qiling import *

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
        if ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
            raise

    ql.os.definesyscall_return(regreturn)


if __name__ == "__main__":
    ql = Qiling(["rootfs/arm_linux/bin/arm_hello"], "rootfs/arm_linux", output = "debug")
    ql.set_syscall(0x04, my_syscall_write)
    ql.set_syscall("write", my_syscall_write)
    ql.run()
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

