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


### ql.set_api()

- Mostly used in Windows API or posix's Libc function replacement

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
- Example below shows replace parameter of syscall 0x1 with onEnter_write
```python
from qiling import *
from qiling.const import *

def onEnter_write(ql, arg1, arg2, arg3, *args):
    print("enter write syscall!")
    ql.reg.rsi = arg2 + 1
    ql.reg.rdx = arg3 - 1

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", output="debug")
    ql.set_syscall(1, onEnter_write, QL_INTERCEPT.ENTER)
    ql.run()
```

- However, Windows and UEFI usage is different from posix.
- All decorator's value need to be return accordingly 
```python
from qiling import *
from qiling.const import *

def my_onenter(ql, param_num, params, func, args, kwargs):
    ql.nprint("\n+++++++++\nmy OnEnter")
    ql.nprint("params: %s" % params)
    ql.nprint("+++++++++\n")
    return  param_num, params, func, args, kwargs

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output = "debug")
    ql.set_api("_cexit", my_onenter, intercept = QL_INTERCEPT.ENTER)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x8664_windows/bin/x8664_hello.exe"], "rootfs/x8664_windows")
```


### On exit interceptor with ql.set_api()
- Hijack return value after OS APIs or syscall execution
- Example below shows replace output result of syscall 0x1 with onExit_write
```python
from qiling import *
from qiling.const import *

def onExit_write(ql, arg1, arg2, arg3, *args):
    print("exit write syscall!")
    ql.reg.rax = arg3 + 1

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", output="debug")
    ql.set_syscall(1, onExit_write, QL_INTERCEPT.EXIT)
    ql.run()
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

