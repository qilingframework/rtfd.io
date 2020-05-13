---
title: Hook
---

### ql.hook_address()

- hooking a specific address and call a function
```python
    def stop(ql):
        ql.nprint("killerswtichfound")
        ql.console = False
        ql.nprint("No Print")
        ql.emu_stop()

    ql = Qiling(["../examples/rootfs/x86_windows/bin/wannacry.bin"], "../examples/rootfs/x86_windows")
    ql.hook_address(stop, 0x40819a)
    ql.run()
```

### ql.hook_code()

- hooking every instruction with self defined function
```python
def print_asm(ql, address, size):
    buf = ql.mem.read(address, size)
    for i in md.disasm(buf, address):
        print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux")
    ql.hook_code(print_asm)
    ql.run()
```

### ql.hook_block()
- hooking a block of code
```python
def ql_hook_block_disasm(ql, address, size):
    ql.nprint("\n[+] Tracing basic block at 0x%x" % (address))

ql.hook_block(ql_hook_block_disasm)
```

### ql.hook_intno()

- hooking interupt number to invoke a custom fuction
```
ql.hook_intno(hook_syscall, 0x80)
```

### ql.hook_insn()

- hooking specific interupt number to invoke a custom fuction
```
ql.hook_insn(hook_syscall, UC_X86_INS_SYSCALL)
```


### ql.hook_int()
- interupt
```
ql.hook_intr()
```

### ql.hook_mem_unmapped()
```
```

### ql.hook_mem_read_invalid()
```
```

### ql.hook_mem_write_invalid()
```
```

### ql.hook_mem_fetch_invalid()
```
```

### qll.hook_mem_invalid()
```
```

### ql.hook_mem_read()

- monitoring a process performing memory read on a specific address
```python
def _mem_read(ql, addr, size, value):
    print("demo for ql.hook_mem_read")

ql.hook_mem_read(_mem_read, 0xffffdef4)
```

### ql.hook_mem_write()

- monitoring a process performing memory write on a specific address
```python
def _mem_write(ql, addr, size, value):
    print("demo for ql.hook_mem_read")

ql.hook_mem_write(_mem_write, 0xffffdef4)
```

### ql.hook_mem_fetch()

- monitoring a process performing memory fetch on a specific address
```python
def _mem_fetch(ql, addr, size, value):
    print("demo for ql.hook_mem_read")

ql.hook_mem_fetch(_mem_write, 0xffffdef4)
```

### ql.hook_del()
```
```

### ql.clear_hooks() 
- clear all hooks
```
ql.clear_hooks()
```
