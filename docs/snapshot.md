---
title: Snapshot
---

### Qiling: save and restore
- save and restore current Qiling state
```python
ql_qll = ql.save()
ql.restore(ql_all)
```

Addition save option will be:
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