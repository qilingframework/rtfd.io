---
title: Demo
---

### Qiling framework emulates a Windows EXE on a Linux machine.

```python
from qiling import *

# sandbox to emulate the EXE
def my_sandbox(path, rootfs):
    # setup Qiling engine
    ql = Qiling(path, rootfs)
    # now emulate the EXE
    ql.run()

if __name__ == "__main__":
    # execute Windows EXE under our rootfs
    my_sandbox(["examples/rootfs/x86_windows/bin/x86_hello.exe"], "examples/rootfs/x86_windows")
```

### Using Qiling framework to dynamically patch a Windows crackme, make it always display "Congratulation" dialog.

```python
from qiling import *

def force_call_dialog_func(ql):
    # get DialogFunc address
    lpDialogFunc = ql.unpack32(ql.mem.read(ql.reg.esp - 0x8, 4))
    # setup stack memory for DialogFunc
    ql.stack_push(0)
    ql.stack_push(1001)
    ql.stack_push(273)
    ql.stack_push(0)
    ql.stack_push(0x0401018)
    # force EIP to DialogFunc
    ql.reg.eip = lpDialogFunc


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)
    # NOP out some code
    ql.patch(0x004010B5, b'\x90\x90')
    ql.patch(0x004010CD, b'\x90\x90')
    ql.patch(0x0040110B, b'\x90\x90')
    ql.patch(0x00401112, b'\x90\x90')
    # hook at an address with a callback
    ql.hook_address(force_call_dialog_func, 0x00401016)
    ql.run()


if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/Easy_CrackMe.exe"], "rootfs/x86_windows")
```

### GDBserver with IDAPro demo

Solving a simple CTF challenge with Qiling Framework and IDAPro

[![Solving a simple CTF challenge with Qiling Framework and IDAPro](https://i.ytimg.com/vi/SPjVAt2FkKA/0.jpg)](https://www.youtube.com/watch?v=SPjVAt2FkKA "Video DEMO 2")

### Fuzzing with Qiling Unicornalf

More information on fuzzing with Qiling Unicornalf can be found [here](https://github.com/qilingframework/qiling/tree/dev/examples/fuzzing/README.md).

[![qiling DEMO 2: Fuzzing with Qiling Unicornalf](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/qilingfzz-s.png)](https://raw.githubusercontent.com/qilingframework/qiling/dev/examples/fuzzing/qilingfzz.png "Demo #2 Fuzzing with Qiling Unicornalf")

### Emulating ARM router firmware on Ubuntu X64 machine

Qiling Framework hot-patch and emulates ARM router's /usr/bin/httpd on a X86_64Bit Ubuntu

[![qiling DEMO 3: Fully emulating httpd from ARM router firmware with Qiling on Ubuntu X64 machine](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/demo3-en.jpg)](https://www.youtube.com/watch?v=Nxu742-SNvw "Demo #3 Emulating ARM router firmware on Ubuntu X64 machine")

### Emulating UEFI

Qiling Framework emulates UEFI

[![qiling DEMO 4: Emulating UEFI](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/demo4-s.png)](https://raw.githubusercontent.com/qilingframework/qilingframework.github.io/master/images/demo4-en.png "Demo #4 Emulating UEFI")

---

### Qltool

Qiling also provides a friendly tool named `qltool` to quickly emulate shellcode & executable binaries.

With qltool, easy execution can be performed:


With shellcode:

```
$ ./qltool shellcode --os linux --arch arm --hex -f examples/shellcodes/linarm32_tcp_reverse_shell.hex
$ ./qltool shellcode --os linux --arch x86 --asm -f examples/shellcodes/lin32_execve.asm
$ ./qltool shellcode --os linux --arch arm --hex -f examples/shellcodes/linarm32_tcp_reverse_shell.hex --strace
```

With binary file:

```
$ ./qltool run -f examples/rootfs/x8664_linux/bin/x8664_hello --rootfs  examples/rootfs/x8664_linux/
$ ./qltool run -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux
```

With UEFI file:

```
$ ./qltool run -f examples/rootfs/x8664_efi/bin/TcgPlatformSetupPolicy --rootfs examples/rootfs/x8664_efi --env examples/rootfs/x8664_efi/rom2_nvar.pickel
```

With binary and GDB debugger enable:

```
$ ./qltool run -f examples/rootfs/x8664_linux/bin/x8664_hello --gdb 127.0.0.1:9999 --rootfs examples/rootfs/x8664_linux
```

With binary file and argv:

```
$ ./qltool run -f examples/rootfs/x8664_linux/bin/x8664_args --rootfs examples/rootfs/x8664_linux --args test1 test2 test3
$ ./qltool run --rootfs examples/rootfs/x8664_linux examples/rootfs/x8664_linux/bin/x8664_args test1 test2 test3
```

with binary file and various output format:

```
$ ./qltool run -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux --output=disasm
$ ./qltool run -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux --strace
```
