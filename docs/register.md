---
title: Register
---

### Reading

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

### Writing
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

##### Weading
```
ql.reg.arch_pc
```

```
ql.reg.arch_pc
```

##### Writing
```
ql.reg.arch_pc = 0xFF
```

```
ql.reg.arch_pc = 0xFF
```