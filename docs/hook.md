---
title: Hook
---

### Overview

Qiling offers availability of various hooks including access to a address, execution of instructions, interrupts etc. A hook is installed by `ql.hook_*` function series, by offering necessary parameters (e.g. addresses, interrupt numbers) and a callback function, with some optional values:

- `user_data`: any data that will be passed to callback function
- `begin`: range start of the program counter
- `end`: range end of the program counter
(the hook will be triggered when `begin` & `end` are not set or `begin <= program counter <= end` holds true)

When the hook is triggered, the previous callback function will be called with some meta information about this hook (`user_data` is included if provided).

### Usage

##### ql.hook_address(callback, address, user_data=None)

Hook all access to a specific address with the callback form `callback(ql)`.

```python
def stop(ql):
    ql.nprint("killerswtichfound")
    ql.nprint("No Print")
    ql.emu_stop()

if __name__ == "__main__":
    ql = Qiling(["../examples/rootfs/x86_windows/bin/wannacry.bin"], "../examples/rootfs/x86_windows")
    ql.hook_address(stop, 0x40819a)
    ql.run()
```

##### ql.hook_code(callback, user_data=None, begin=1, end=0)

Hook all instructions with the callback form `callback(ql, address, size)`.

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

##### ql.hook_block(callback, user_data=None, begin=1, end=0)

Hook a block of code with the callback form `callback(ql, address, size)`.

```python
def ql_hook_block_disasm(ql, address, size):
    ql.nprint("\n[+] Tracing basic block at 0x%x" % (address))

ql.hook_block(ql_hook_block_disasm)
```

##### ql.hook_insn(callback, type, user_data=None, begin=1, end=0)

Hook specific instructions by `type` with callback form `callback(ql)`.

The `type` indicates the instruction type. It should be among `UC_X86_INS_IN`, `UC_X86_INS_OUT`, `UC_X86_INS_SYSCALL`, `UC_X86_INS_SYSENTER`.

```python
from unicorn.x86_const import *

def on_syscall(ql):
    print("Doing syscall by x86 SYSCALL instruction.")

ql.hook_insn(on_syscall, UC_X86_INS_SYSCALL)
```

##### ql.hook_intno(callback, intno, user_data=None)

Hook specific interrupts by `intno` with callback form `callback(ql, intno)`.

```python
def on_syscall(ql, intno):
    print("Doing syscall by int 0x80.")

if __name__ == "__main__":
    ql = Qiling(["rootfs/x86_linux/bin/x86_hello"], "rootfs/x86_linux")
    ql.hook_intno(on_syscall, 0x80)
    ql.run()
```

##### ql.hook_intr(callback, user_data=None, begin=1, end=0)

Hook all interrupts with callback form `callback(ql, intno)`.

```python
def on_interrupt(ql, intno):
    print("Interrupt number %x" % (intno))

if __name__ == "__main__":
    ql = Qiling(["rootfs/x86_linux/bin/x86_hello"], "rootfs/x86_linux")
    ql.hook_intr(on_interrupt)
    ql.run()
```

##### ql.hook_mem_invalid(callback, user_data=None, begin=1, end=0)
##### ql.hook_mem_valid(callback, user_data=None, begin=1, end=0)

Hook valid / invalid access to memory with callback form `callback(ql, access, address, size, value)`. An invalid access includes unmapped, protected memories

Callback parameter `access` is a value in `uc_mem_type` to indicate the access type:
  - `UC_MEM_READ`: normal read from the memory (valid)
  - `UC_MEM_WRITE`: normal write to the memory (valid)
  - `UC_MEM_FETCH`: normal fetch of the memory (valid)
  - `UC_MEM_READ_UNMAPPED`: read from unmapped memory (invalid)
  - `UC_MEM_WRITE_UNMAPPED`: write to unmapped memory (invalid)
  - `UC_MEM_FETCH_UNMAPPED`: fetch of unmapped memory (invalid)
  - `UC_MEM_WRITE_PROT`: write to protected memory (invalid)
  - `UC_MEM_READ_PROT`: read from protected memory (invalid)
  - `UC_MEM_FETCH_PROT`: fetch of protected memory (invalid)
  - `UC_MEM_READ_AFTER`: post-read from the memory (valid)

```python
def on_mem_valid(ql, access, address, size, value):
    print('Valid access', access, address, size, value)

def on_mem_invalid(ql, access, address, size, value):
    print('Invalid access', access, address, size, value)

    PAGE_SIZE = ql.mem.pagesize
    aligned = ql.mem.align(address)

    ql.mem.map(aligned, PAGE_SIZE)
    ql.mem.write(aligned, b'Q' * PAGE_SIZE)

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/mem_invalid_access"], "rootfs/x8664_linux")
    ql.hook_mem_invalid(on_mem_invalid)
    ql.hook_mem_valid(on_mem_valid)
    ql.run()
```

##### ql.hook_mem_read(callback, user_data=None, begin=1, end=0)
##### ql.hook_mem_write(callback, user_data=None, begin=1, end=0)
##### ql.hook_mem_fetch(callback, user_data=None, begin=1, end=0)

Hook specific types of *valid* memory access with callback form `callback(ql, access, address, size, value)`.

Different methods limit the memory access types (callback `access`) to:
- `ql.hook_mem_read`: all valid reads (`UC_MEM_READ`)
- `ql.hook_mem_write`: all valid writes (`UC_MEM_WRITE`)
- `ql.hook_mem_fetch`: all valid fetches (`UC_MEM_FETCH`)

Usages are similar to `ql.hook_mem_valid`.

##### ql.hook_mem_unmapped(callback, user_data=None, begin=1, end=0)
##### ql.hook_mem_read_invalid(callback, user_data=None, begin=1, end=0)
##### ql.hook_mem_write_invalid(callback, user_data=None, begin=1, end=0)
##### ql.hook_mem_fetch_invalid(callback, user_data=None, begin=1, end=0)

Hook specific types of *invalid* memory access with callback form `callback(ql, access, address, size, value)`.

Different methods limit the memory access types (callback `access`) to:
- `ql.hook_mem_unmapped`: all unmapped access (`UC_MEM_READ_UNMAPPED | UC_MEM_WRITE_UNMAPPED | UC_MEM_FETCH_UNMAPPED`)
- `ql.hook_read_invalid`: all invalid reads (`UC_MEM_READ_UNMAPPED | UC_MEM_READ_PROT`)
- `ql.hook_mem_write_invalid`: all invalid writes (`UC_MEM_WRITE_UNMAPPED | UC_MEM_WRITE_PROT`)
- `ql.hook_fetch_invalid`: all invalid fetches (`UC_MEM_FETCH_UNMAPPED | UC_MEM_FETCH_PROT`)

Usages are similar to `ql.hook_mem_invalid`.

##### ql.hook_del(hook_ret)

Delete a hook. Parameter `hook_ret` is the return result of a `ql.hook_*` function.

```python
def hook_syscall(ql, intno):
    print("Doing syscall by int 0x80.")

if __name__ == "__main__":
    ql = Qiling(["rootfs/x86_linux/bin/x86_hello"], "rootfs/x86_linux")
    hook_ret = ql.hook_intno(hook_syscall, 0x80)
    ql.hook_del(hook_ret)
    ql.run()
```

##### ql.clear_hooks()

Remove all installed hooks.

```python
ql.clear_hooks()
```
