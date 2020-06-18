---
title: Qltool
---

Qiling Framework also provides a friendly tool named `qltool` to quickly emulate shellcode & executable binaries.

With qltool, easy execution can be performed:


### shellcode:

```bash
$ ./qltool shellcode --os linux --arch arm --hex -f examples/shellcodes/linarm32_tcp_reverse_shell.hex
$ ./qltool shellcode --os linux --arch x86 --asm -f examples/shellcodes/lin32_execve.asm
$ ./qltool shellcode --os linux --arch arm --hex -f examples/shellcodes/linarm32_tcp_reverse_shell.hex --strace
```

### binary file:

```bash
$ ./qltool run -f examples/rootfs/x8664_linux/bin/x8664_hello --rootfs  examples/rootfs/x8664_linux/
$ ./qltool run -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux
```

### UEFI file:

```bash
$ ./qltool run -f examples/rootfs/x8664_efi/bin/TcgPlatformSetupPolicy --rootfs examples/rootfs/x8664_efi --env examples/rootfs/x8664_efi/rom2_nvar.pickel
```

### GDB debugger enable:

```bash
$ ./qltool run -f examples/rootfs/x8664_linux/bin/x8664_hello --gdb 127.0.0.1:9999 --rootfs examples/rootfs/x8664_linux
```

### Binary file and argv:

```bash
$ ./qltool run -f examples/rootfs/x8664_linux/bin/x8664_args --rootfs examples/rootfs/x8664_linux --args test1 test2 test3
$ ./qltool run --rootfs examples/rootfs/x8664_linux examples/rootfs/x8664_linux/bin/x8664_args test1 test2 test3
```

### Binary file and various output format:

```bash
$ ./qltool run -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux --output=disasm
$ ./qltool run -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux --strace
```

### Binary file and env:
```bash
$ ./qltool run -f jexamples/rootfs/x8664_linux/bin/tester --rootfs jexamples/rootfs/x8664_linux --env '{"LD_PRELOAD":"hijack.so"}' --debug
```