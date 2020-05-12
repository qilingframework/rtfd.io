---
title: Pack and Unpack
---

pack with option "Q"
C Type: unsigned long long 
Size: 8 bytes
```
ql.pack64()
```

unpack with option "Q"
C Type: unsigned long long 
Size: 8 bytes
```
ql.upack64()
```

pack with option "q"
C Type: long 
Size: 8 bytes
```
ql.pack64s()
```

unpack with option "q"
C Type: long 
Size: 8 bytes
```
ql.unpack64s()
```

pack with option "I", with endian check
C Type: unsigned int 
Size: 4 bytes
```
ql.pack32()
```

unpack with option "I", with endian check
C Type: unsigned int 
Size: 4 bytes
```
ql.unpack32()
```

pack with option "i", with endian check
C Type: int 
Size: 4 bytes
```
ql.pack32s
```

unpack with option "i", with endian check
C Type: int 
Size: 4 bytes
```
ql.unpack32s()
```

unpack with option "i"
C Type: int 
Size: 4 bytes
```
unpack32_ne()
```

pack with option "H", with endian check
C Type: unsigned short 
Size: 2 bytes
```
ql.pack16()
```

unpack with option "H", with endian check
C Type: unsigned short 
Size: 2 bytes
```
ql.unpack16()
```

if archbit == 64 then ql.pack64 else ql.pack32
```
ql.pack()
```

if archbit == 64 then ql.unpack64 else ql.unpack32
```
ql.unpack()
```

if archbit == 64 then ql.pack64s else ql.pack32s
```
ql.packs()
```

if archbit == 64 then ql.unpack64s else ql.unpack32s
```
ql.unpacks()
```