---
title: Register
---

### Reading


```
ql.reg.read("EAX")
```
or
```
ql.reg.read(UC_X86_REG_EAX)
```
or
```
eax = ql.reg.eax
```

### Writing
```
ql.reg.write("EAX", 0xFF)
```
or
```
ql.reg.write(UC_X86_REG_EAX, 0xFF)
```
or
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