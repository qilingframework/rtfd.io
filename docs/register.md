to read register

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

to write register
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
