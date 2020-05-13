---
title: Print
---

### ql.print: Qiling style print

```
ql.nprint("this is a test print msg no. %i" % test)
```

### ql.dprint: Debug print

- D_INFO 
> - General debug information
- D_PROT
> - Protocol level debug, print out open file flag
- D_CONT
> - Print out content. File content or content of a tcp stream
- D_RPRT
> - Reporting output, main summarizing purposes

```
test = 1
ql.dprint(D_INFO , "this is a debug msg no. %i" % test)
```