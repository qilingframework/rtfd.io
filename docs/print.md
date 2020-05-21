---
title: Print and Filter
---

### ql.print: Qiling style print

```python
test = "test123"
ql.nprint("this is a test print msg no. %s" % test)
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

```python
test = "test456"
ql.dprint(D_INFO , "this is a debug msg no. %s" % test)
```

### ql.filter

Filter out functions or syscall is possible via ql.filter option. For log and stdio.

```
#!/usr/bin/env python3
from qiling import *

if __name__ == "__main__":
    ql = Qiling(["examples/rootfs/arm_linux/bin/arm_hello"], "examples/rootfs/arm_linux", log_dir="qlog")
    ql.filter = ["open"]
    ql.run()
```