---
title: Hijack
---


```
ql.set_api
```


```
ql.set_syscall
```


Pathch a binary or patch a lib from that load by the binary

```
ql.patch(0x0000000000000575, b'qiling\x00', file_name = b'libpatch_test.so')
ql.patch(0x0000000000000575, b'qiling\x00')  
```

```
ql.compile(ASM, ql.archtype)
```

