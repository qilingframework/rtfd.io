---
title: Pack and Unpack
---


unpack with option Q
```
ql.upack64()
```

pack with option Q
```
ql.pack64()
```

pack with option q
```
ql.pack64s()
```

unpack with option q
```
ql.unpack64s()
```

pack with >I if big endian else, pack with I
```
ql.pack32()
```

unpack with >I if big endian else, pack with I
```
ql.unpack32()
```

unpack with >i if big endian else, pack with i
```
ql.unpack32s()
```

unpack with i
```
unpack32_ne()
```


pack with >i if big endian else pack with i
```
ql.pack32s
```

unpack with >H if big endian else unpack with H 
```
ql.unpack16()
```


pack with >H if big endian else pack with H
```
ql.pack16()
```

if archbit == 64 then ql.pack64 else ql.pack32
```
ql.pack()
```

if archbit == 64 then ql.pack64s else ql.pack32s
```
ql.packs()
```

if archbit == 64 then ql.unpack64 else ql.unpack32
```
ql.unpack()
```

if archbit == 64 then ql.unpack64s else ql.unpack32s
```
ql.unpacks()
```


