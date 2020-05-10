---
title: Register
---

Reference: qiling/arch/register.py

### Read

read from string "exa"
```
ql.reg.read("EAX")
```

read from Unicorn Engine const
```
ql.reg.read(UC_X86_REG_EAX)
```

read eax
```
eax = ql.reg.eax
```

### Write
write 0xFF to "eax"
```
ql.reg.write("EAX", 0xFF)
```

write 0xFF to eax, via Unicorn Engine const
```
ql.reg.write(UC_X86_REG_EAX, 0xFF)
```

write 0xFF to eax
```
ql.reg.eax =  0xFF
```


### Cross architecture registers

This is for pc and sp only.

- Reading from PC/SP on current arch, defined by ql.archtype
```
ql.reg.arch_pc
```

```
ql.reg.arch_sp
```

- Reading to PC/SP on current arch, defined by ql.archtype
```
ql.reg.arch_pc = 0xFF
```

```
ql.reg.arch_sp = 0xFF
```


### Store/Restore current arch register

Store all the current running state register
```
all_registers = ql.reg.store
```

Restore all the save register from all_registers
```
all_registers = ql.reg.restore(all_register)
```

### Get register table
```
ql.reg.table
```

### Get current register name
This will return "eax"
```
ql.reg.name(UC_X86_REG_EAX)
```


### Get register bit
This is for archirecture comes with 64bit and 32bit register

In 64 enviroment this will return 64
```
ql.reg.bit("rax")
```

In 64 enviroment this will return 32
```
ql.reg.bit("eax")
```