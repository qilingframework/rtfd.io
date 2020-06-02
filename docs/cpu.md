---
title: CPU Related API
---

### Save/Restore current running state register

- context_save and context_restore are interfaces to uc_context_save and uc_context_restore.

> - Save all the current running CPU state
```python
all_registers_context = ql.reg.context_save()
```

> - Restore all the saved CPU state
```python
ql.reg.context_restore(all_registers_context)
```
