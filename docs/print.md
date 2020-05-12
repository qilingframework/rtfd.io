---
title: Print
---

### Qiling style print

```
ql.nprint("this is a test print msg no. %i" % test)
```

### dprint or debug print

- D_INFO = 1 # General debug information
- D_PROT = 2 # Protocol level debug, print out open file flag
- D_CONT = 3 # Print out content. File content or content of a tcp stream
- D_RPRT = 4 # Reporting output, main summarizing purposes

```
test = 1
ql.dprint(D_INFO , "this is a debug msg no. %i" % test)
```