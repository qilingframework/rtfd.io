---
title: Hook
---

### ql.hook_address(_callback_: Callable, _address_: int)
Hook a specific address. The registered callback will be invoked upon execution of the specified address.

```python
    from qiling import Qiling

    def stop(ql: Qiling) -> None:
        ql.log.info('killer switch found, stopping')
        ql.emu_stop()

    ql = Qiling([r'examples/rootfs/x86_windows/bin/wannacry.bin'], r'examples/rootfs/x86_windows')

    # have 'stop' called when execution reaches 0x40819a
    ql.hook_address(stop, 0x40819a)

    ql.run()
```

### ql.hook_code(_callback_: Callable, _user_data_: Any = None)
Hook all instructions. The registered callback will be invoked on every assembly instruction, just before it gets executed

```python
from capstone import Cs
from qiling import Qiling
from qiling.const import QL_VERBOSE

def simple_diassembler(ql: Qiling, address: int, size: int, md: Cs) -> None:
    buf = ql.mem.read(address, size)

    for insn in md.disasm(buf, address):
        ql.log.debug(f':: {insn.address:#x} : {insn.mnemonic:24s} {insn.op_str}')

if __name__ == "__main__":
    ql = Qiling([r'examples/rootfs/x8664_linux/bin/x8664_hello'], r'examples/rootfs/x8664_linux', verbose=QL_VERBOSE.DEBUG)

    # have 'simple_disassembler' called on each instruction, passing a Capstone disassembler instance bound to
    # the underlying architecture as an optional argument
    ql.hook_code(simple_diassembler, user_data=ql.arch.disassembler)

    ql.run()
```

### ql.hook_block()
- hooking a block of code
```python
def ql_hook_block_disasm(ql, address, size):
    ql.log.debug("\n[+] Tracing basic block at 0x%x" % (address))

ql.hook_block(ql_hook_block_disasm)
```

### ql.hook_intno()

- hooking interupt number to invoke a custom fuction
```python
ql.hook_intno(hook_syscall, 0x80)
```

### ql.hook_insn()
Intercept instructions of a specific type. The supported instruction types are limited to the ones supported by Unicorn.

Supported Intel instructions:
- `UC_X86_INS_SYSCALL`
- `UC_X86_INS_IN`
- `UC_X86_INS_OUT`

```python
from typing import Tuple
from unicorn.x86_const import UC_X86_INS_IN

def handle_in(ql: Qiling, port: int, size: int) -> Tuple[int, int]:
    # call some function to look up the value held in the specified port (not implemented by Qiling)
    value = lookup_port_value(port, size)

    ql.log.debug(f'reading from port {port:#x}, size {size:d} -> {value:#0{size * 2 + 2}x}')

    # return a tuple indicating other hooks may be processed (0) and the read value (value)
    return (0, value)

ql.hook_insn(handle_in, UC_X86_INS_IN)
```

### ql.hook_int()
- interupt
```python
ql.hook_intr()
```

### ql.hook_mem_unmapped()
Intercept memory accesses to unmapped addresses. That includes memory reads, writes and fetches.
```python
```

### ql.hook_mem_read_invalid()
```python
```

### ql.hook_mem_write_invalid()
```python
```

### ql.hook_mem_fetch_invalid()
```python
```

### qll.hook_mem_invalid()
Intercept invalid memory accesses. That includes memory accesses to unmapped addresses, and protection violations (e.g. writing to a read-only memory range, or fetching from a non-executable memory range).
```python
```

### ql.hook_mem_read(_callback_: Callable, _begin_: int = 1, _end_: int = 0)
Intercept memory reads from memory locations between `begin` and `end`. The registered callback will be invoked on every attempt to read from the specified memory range, just before the value is read.

Notes:
- If `end` is not specified, only reads to the address specified in `begin` will be intercepted
- If both `begin` and `end` are not specified, all memory reads will be intercepted
- The callback `value` argument is unused (always 0)
- The callback may alter the value in memory before it is read (i.e. write a new value to that memory location)

```python
from unicorn.unicorn_const import UC_MEM_READ

def mem_read(ql: Qiling, access: int, address: int, size: int, value: int) -> None:
    # only read accesses are expected here
    assert access == UC_MEM_READ

    ql.log.debug(f'intercepted a memory read from {address:#x}')

stack_lbound = ql.arch.regs.arch_sp
stack_ubound = ql.arch.regs.arch_sp - 0x1000

# hook all reads from the top page of the stack
ql.hook_mem_read(mem_read, begin=stack_ubound, end=stack_lbound)
```

### ql.hook_mem_write(_callback_: Callable, _begin_: int = 1, _end_: int = 0)
Intercept memory writes to memory locations between `begin` and `end`. The registered callback will be invoked on every attempt to write to the specified memory range, just before the value is written.

Notes:
- If `end` is not specified, only writes to the address specified in `begin` will be intercepted
- If both `begin` and `end` are not specified, all memory writes will be intercepted

```python
from unicorn.unicorn_const import UC_MEM_WRITE

def mem_write(ql: Qiling, access: int, address: int, size: int, value: int) -> None:
    # only write accesses are expected here
    assert access == UC_MEM_WRITE

    ql.log.debug(f'intercepted a memory write to {address:#x} (value = {value:#x})')

trigger_address = 0xdecaf000

# hook all writes to 'trigger_address'
ql.hook_mem_write(mem_write, trigger_address)
```

### ql.hook_mem_fetch()

- monitoring a process performing memory fetch on a specific address
```python
```

### ql.hook_del()
```python
```

### ql.clear_hooks() 
- clear all hooks
```python
ql.clear_hooks()
```
