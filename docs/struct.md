---
title: Pack and Unpack
---
### ql.pack()
If archbit == 64 then ql.pack64 else ql.pack32
```
ql.pack()
```
###### Pack with option "Q":

- C Type: unsigned long long 
- size: 8 bytes
```
ql.pack64()
```

###### Pack with option "I", with endian check:

- C Type: unsigned int 
- size: 4 bytes
```
ql.pack32()
```

### ql.unpack()
if archbit == 64 then ql.unpack64 else ql.unpack32
```
ql.unpack()
```

###### Unpack with option "Q":

- C Type: unsigned long long 
- size: 8 bytes
```
ql.upack64()
```

###### Unpack with option "I", with endian check:
- C Type: unsigned int 
- size: 4 bytes
```
ql.unpack32()
```

### ql.packs()
if archbit == 64 then ql.pack64s else ql.pack32s
```
ql.packs()

```

###### Pack with option "q":

- C Type: long 
- size: 8 bytes
```
ql.pack64s()
```
###### Pack with option "i", with endian check:

- C Type: int 
- size: 4 bytes
```
ql.pack32s
```

### ql.unpacks()
if archbit == 64 then ql.unpack64s else ql.unpack32s
```
ql.unpacks()
```

###### Unpack with option "q":

- C Type: long 
- size: 8 bytes
```
ql.unpack64s()
```

###### Unpack with option "i", with endian check:

- C Type: int 
- size: 4 bytes
```
ql.unpack32s()
```

###### Unpack with option "i":

- C Type: int 
- size: 4 bytes
```
unpack32_ne()
```

###### Pack with option "H", with endian check:

- C Type: unsigned short 
- size: 2 bytes
```
ql.pack16()
```

###### Unpack with option "H", with endian check:

- C Type: unsigned short 
- size: 2 bytes
```
ql.unpack16()
```