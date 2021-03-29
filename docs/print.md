---
title: Print and Filter
---

### Log Printing

We use python `logging` module directly. You can use them directly in your callbacks.

```python
logging.info("Hello from Qiling Framework!")
```

`ql.nprint` and `ql.dprint` will be depreciated and removed in a later release.

### Verbosity

By default, Qiling only outputs of `logging.INFO` level to terminal. You may configure such behavior in different ways.

#### console

```python
ql = Qiling(['/bin/ls'], "examples/rootfs/x86_linux", console=False)
```

`console=False` will disable terminal outputs.

#### verbose

```python
ql = Qiling(['/bin/ls'], "examples/rootfs/x86_linux", verbose=QL_VERBOSE.DEFAULT)
```

- QL_VERBOSE.OFF(0): logging.WARNING, almost no additional logs except the program output.
- QL_VERBOSE.DEFAULT(1): logging.INFO, the default logging level.
- QL_VERBOSE.DEBUG(4): logging.DEBUG.
- QL_VERBOSE.DISASM(10): Disasm each executed instruction.
- QL_VERBOSE.DUMP(20): The most verbose output, dump registers and disasm the function blocks.

Note that `verbose` can be configured dynamically.

### ql.filter

Filter some specific logs. Very useful if you would like to achieve something like `strace`.

```python
#!/usr/bin/env python3
from qiling import *

if __name__ == "__main__":
    ql = Qiling(["examples/rootfs/arm_linux/bin/arm_hello"], "examples/rootfs/arm_linux", log_dir="qlog")
    ql.filter = "^open"
    ql.run()
```

Note that the content of filter is considered as a regular expression.
