---
title: Register
---

Reference: qiling/arch/register.py

### Read

- Reading from string "exa"
```
ql.reg.read("EAX")
```

- Reading from Unicorn Engine const
```
ql.reg.read(UC_X86_REG_EAX)
```

- Reading eax
```
eax = ql.reg.eax
```

### Write

- Writing 0xFF to "eax"
```
ql.reg.write("EAX", 0xFF)
```

- Writing 0xFF to eax, via Unicorn Engine const
```
ql.reg.write(UC_X86_REG_EAX, 0xFF)
```

- Writing 0xFF to eax
```
ql.reg.eax =  0xFF
```


### Cross architecture registers

- This is for pc and sp only.

```
ql.reg.arch_pc
ql.reg.arch_sp
```

> - Reading from PC/SP on current arch, defined by ql.archtype
```
ql.reg.arch_pc = 0xFF
ql.reg.arch_sp = 0xFF
```


### Save/Restore current arch register

- 2 options to save all the current running state register
```
all_registers = ql.reg.save
all_registers_context = ql.reg.context_save
```

- 2 options to restore all the saved registers from "all_registers"
```
ql.reg.restore(all_registers)
ql.reg.context_restore(all_registers_context)
```


### Get register table

- Getting the list of current arch register table
```
ql.reg.table
```

### Get current register name

- This will return "eax"
```
ql.reg.name(UC_X86_REG_EAX)
```


### Get register bit

- This is for architecture that comes with 64bit and 32bit register

> - In 64bit environment this will return 64
```
ql.reg.bit("rax")
```

> - In 64bit environment this will return 32
```
ql.reg.bit("eax")
```
