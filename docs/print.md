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

#### output

```python
ql = Qiling(['/bin/ls'], "examples/rootfs/x86_linux", output="off")
```

`output` is a parameter for compatibility. Its possible values are as follows.

- "default": equals to "output=None", do nothing.
- "off": an alias to "default".
- "debug": set the log level to logging.DEBUG.
- "disasm": diasm each executed instruction.
- "dump": the most verbose output, dump registers and diasm the function blocks.

Note that `output` can be configured dynamically.

#### verbose

```python
ql = Qiling(['/bin/ls'], "examples/rootfs/x86_linux", verbose=5)
```

- 0  : logging.WARNING, almost no additional logs except the program output.
- >=1: logging.INFO, the default logging level.
- >=4: logging.DEBUG.

`verbose` is another parameter for compatibiliy, which is an alias of different logging levels.

Note that `verbose` can be configured dynamically.

### ql.filter

Filter some specific logs. Very useful if you would like to achieve something like `strace`.

```
#!/usr/bin/env python3
from qiling import *

if __name__ == "__main__":
    ql = Qiling(["examples/rootfs/arm_linux/bin/arm_hello"], "examples/rootfs/arm_linux", log_dir="qlog")
    ql.filter = ["^open"]
    ql.run()
```

Note that the content of filter is considered as a regular expression.
