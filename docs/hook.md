---
title: Hook
---

hook_address: hook a specific address and call a function
```
    def stop(ql):
        ql.nprint("killerswtichfound")
        ql.console = False
        ql.nprint("No Print")
        ql.emu_stop()

    ql = Qiling(["../examples/rootfs/x86_windows/bin/wannacry.bin"], "../examples/rootfs/x86_windows")
    ql.hook_address(stop, 0x40819a)
    ql.run()
```

hook_code: hook every instruction with self defined function
```
def print_asm(ql, address, size):
    buf = ql.mem.read(address, size)
    for i in md.disasm(buf, address):
        print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux")
    ql.hook_code(print_asm)
    ql.run()
```

hook_intno: hook interupt number
```
ql.hook_intno(self.hook_syscall, 0x80)
```

hook_insn: 
```
self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
```

hook_block:
```
def ql_hook_block_disasm(ql, address, size):
    ql.nprint("\n[+] Tracing basic block at 0x%x" % (address))

ql.hook_block(ql_hook_block_disasm)
```

hook_intr: interupt
```
```

hook_mem_unmapped
```
```

hook_mem_read_invalid
```
```

hook_mem_write_invalid
```
```

hook_mem_fetch_invalid
```
```

hook_mem_invalid
```
```

hook_mem_read: monitory does of perform memory read on a specific address
```
def _mem_read(ql, addr, size, value):
    print("demo for ql.hook_mem_read")

ql.hook_mem_read(_mem_read, 0xffffdef4)
```

hook_mem_write: monitory does of perform memory write on a specific address
```
def _mem_write(ql, addr, size, value):
    print("demo for ql.hook_mem_read")

ql.hook_mem_write(_mem_write, 0xffffdef4)
```

hook_mem_fetch: monitory does of perform memory fetch on a specific address
```
def _mem_fetch(ql, addr, size, value):
    print("demo for ql.hook_mem_read")

ql.hook_mem_fetch(_mem_write, 0xffffdef4)
```

hook_del
```
```

clear_hooks: clear all hooks
```
ql.clear_hooks()
```