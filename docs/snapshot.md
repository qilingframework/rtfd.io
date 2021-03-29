---
title: Snapshot & Partial Execution
---

### Partial Execution

- sleep_hello will sleep for 3600 seconds and "print helloworld"
- This is the C code, it will sleep for 3600 seconds before print helloworld
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void func_hello()
{
    printf("Hello, World!\n");
    return;
}

int main(int argc, const char **argv)
{
    printf("sleep 3600 seconds...\n");
    sleep(3600);
    printf("wake up.\n");
    func_hello();
    return 0;
}
```
- The example below will stop at 0x1094, right before sleep() and save the current emulation state
- Rerun sleep_hello and start at 0x10bc which is right after the sleep 3600 seconds

```python
from qiling.const import QL_VERBOSE

def dump(ql, *args, **kw):
    ql.save(reg=False, cpu_context=True, snapshot="/tmp/snapshot.bin")
    ql.emu_stop()

ql = Qiling(["../examples/rootfs/x8664_linux/bin/sleep_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEFAULT)
X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
ql.hook_address(dump, X64BASE + 0x1094)
ql.run()

ql = Qiling(["../examples/rootfs/x8664_linux/bin/sleep_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
ql.restore(snapshot="/tmp/snapshot.bin")
begin_point = X64BASE + 0x109e
end_point = X64BASE + 0x10bc
ql.run(begin = begin_point, end = end_point)
```

### Qiling: save and restore
- save and restore current Qiling state
```python
ql_all = ql.save()
ql.restore(ql_all)
```

Additional save options are:
```
ql.save(mem= True, reg= True, fd= True, cpu_ctx= False)
```

### File Descriptor: save and restore
- Save and restore current file descriptor state
```python
all_fd = ql.fd.save()
ql.fd.restore(all_fd)
```

### CPU State: save and restore
- context_save and context_restore are interfaces to uc_context_save and uc_context_restore.
> - Save all the current running CPU state
```python
all_registers_context = ql.reg.context_save()
```

> - Restore all the saved CPU state
```python
ql.reg.context_restore(all_registers_context)
```

### Memory: save and restore
- Save and restore current memory state
```python
all_mem = ql.mem.save()
ql.mem.restore(all_mem)
```

### Register: save and restore
- Save all the current running state register
- replace eip with new value
```python
all_registers = ql.reg.save()
all_registers["eip"] = 0xaabbccdd
```

- Restore all the saved registers from "all_registers"
```python
ql.reg.restore(all_registers)
```
