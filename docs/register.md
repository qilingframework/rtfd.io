---
title: Register
---

Reference: qiling/arch/register.py

### Read

- Reading from string "exa"

```python
ql.reg.read("EAX")
```

- Reading from Unicorn Engine const

```python
ql.reg.read(UC_X86_REG_EAX)
```

- Reading eax

```python
eax = ql.reg.eax
```


### Write

- Writing 0xFF to "eax"

```python
ql.reg.write("EAX", 0xFF)
```

- Writing 0xFF to eax, via Unicorn Engine const

```python
ql.reg.write(UC_X86_REG_EAX, 0xFF)
```

- Writing 0xFF to eax

```python
ql.reg.eax =  0xFF
```


### Cross architecture registers

- This is for pc and sp only.

```python
ql.reg.arch_pc
ql.reg.arch_sp
```

> - Reading from PC/SP on current arch, defined by ql.archtype

```python
ql.reg.arch_pc = 0xFF
ql.reg.arch_sp = 0xFF
```


### Save/Restore current arch register

- 2 options to save all the current running state register
- context_save and context_restore is interface to uc_context_save and uc_context_register. It save more register compare to ql.reg.save/restore

```python
all_registers = ql.reg.save
all_registers_context = ql.reg.context_save
```

- 2 options to restore all the saved registers from "all_registers"

```python
ql.reg.restore(all_registers)
ql.reg.context_restore(all_registers_context)
```


### Get register table

- Getting the list of current arch register table

```python
ql.reg.table
```


### Get current register name

- This will return "eax"

```python
ql.reg.name(UC_X86_REG_EAX)
```


### Get register bit

- This is for architecture that comes with 64bit and 32bit register

> - In 64bit environment this will return 64

```python
ql.reg.bit("rax")
```

> - In 64bit environment this will return 32

```python
ql.reg.bit("eax")
```
