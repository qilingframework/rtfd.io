---
title: Pack and Unpack
---
### ql.pack()
If archbit == 64 then ql.pack64 else ql.pack32
```
ql.pack()
```
- pack for 64bit data
> - Pack with option "Q":
> - C Type: unsigned long long 
> - Size: 8 bytes
```
ql.pack64()
```

- pack for 32bit data
> - Pack with option "I", with endian check:
> - C Type: unsigned int 
> - Size: 4 bytes
```
ql.pack32()
```

### ql.unpack()
if archbit == 64 then ql.unpack64 else ql.unpack32
```
ql.unpack()
```

- unpack for 64bit data
> - Unpack with option "Q":
> - C Type: unsigned long long 
> - Size: 8 bytes
```
ql.upack64()
```

- unpack for 32bit data
> - Unpack with option "I", with endian check:
> - C Type: unsigned int 
> - Size: 4 bytes
```
ql.unpack32()
```

### ql.packs()
if archbit == 64 then ql.pack64s else ql.pack32s
```
ql.packs()
```

- packs for 64bit data
> - Pack with option "q":
> - C Type: long 
> - Size: 8 bytes
```
ql.pack64s()
```

- packs for 32bit data
> - Pack with option "i", with endian check:
> - C Type: int 
> - Size: 4 bytes
```
ql.pack32s
```

### ql.unpacks()
if archbit == 64 then ql.unpack64s else ql.unpack32s
```
ql.unpacks()
```

- unpacks for 64bit data
> - Unpack with option "q":
> - C Type: long 
> - Size: 8 bytes
```
ql.unpack64s()
```

- unpacks for 32bit  data
> - Unpack with option "i", with endian check:
> - C Type: int 
> - Size: 4 bytes
```
ql.unpack32s()
```

- pack for 16bits data
> - Pack with option "H", with endian check:
> - C Type: unsigned short 
> - Size: 2 bytes
```
ql.pack16()
```

- unpack for 16bit data
> - Unpack with option "H", with endian check:
> - C Type: unsigned short 
> - Size: 2 bytes
```
ql.unpack16()
```

### ql.unpack32_ne()
> - Unpack with option "i":
> - C Type: int 
> - Size: 4 bytes
```
unpack32_ne()
```