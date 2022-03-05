---
title: Register
---

Reference: qiling/arch/register.py

### Read

- Reading from string "eax"

```python
ql.arch.regs.read("EAX")
```

- Reading from Unicorn Engine const

```python
ql.arch.regs.read(UC_X86_REG_EAX)
```

- Reading eax

```python
eax = ql.arch.regs.eax
```


### Write

- Writing 0xFF to "eax"

```python
ql.arch.regs.write("EAX", 0xFF)
```

- Writing 0xFF to eax, via Unicorn Engine const

```python
ql.arch.regs.write(UC_X86_REG_EAX, 0xFF)
```

- Writing 0xFF to eax

```python
ql.arch.regs.eax =  0xFF
```


### Cross architecture registers

- This is for pc and sp only.

```python
ql.arch.regs.arch_pc
ql.arch.regs.arch_sp
```

> - Reading from PC/SP on current arch, defined by ql.arch.type

```python
ql.arch.regs.arch_pc = 0xFF
ql.arch.regs.arch_sp = 0xFF
```


### Get register table

- Getting the list of current arch register table

```python
ql.arch.regs.register_mapping()
```


### Get register bit

- This is for architecture that comes with 64bit and 32bit register

> - In 64bit environment this will return 64

```python
ql.arch.reg_bits("rax")
```

> - In 64bit environment this will return 32

```python
ql.arch.reg_bits("eax")
```
