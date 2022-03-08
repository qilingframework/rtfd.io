---
title: Print and Filter
---

### Log Printing

Qiling logging uses Python's `logging` module indirectly, and may be used anywhere Qiling instance is available.

```python
ql.log.info('Hello from Qiling Framework!')
```

### Verbosity

Qiling logging verbosity may configure to various verbosity levels based on one's needs. This does no affect the program's output in any way. By default, Qiling logging verbosity is set to `logging.INFO`.

#### verbose

```python
from qiling.const import QL_VERBOSE

ql = Qiling([r'/bin/ls'], r'examples/rootfs/x86_linux', verbose=QL_VERBOSE.DEBUG)
```

| Verbosity Level       | Desciprtion
| :--                   | :--
| `QL_VERBOSE.DISABLED` | logging is disabled entirely
| `QL_VERBOSE.OFF`      | logging is restricted to warnings, errors and critical entries
| `QL_VERBOSE.DEFAULT`  | info verbosity
| `QL_VERBOSE.DEBUG`    | debug verbosity; increased verbosity
| `QL_VERBOSE.DISASM`   | emit disassembly for every emulated instruction; this implies debug verbosity
| `QL_VERBOSE.DUMP`     | emit cpu context along with disassembled instructions; this implies debug verbosity

Note that Qiling `verbose` property may be configured dynamically throughout the emulation.

### ql.filter

Qiling log entires may be filteres using a regular expression. That may help filtering excessive logs and focusing on what matters.

```python
from qiling import Qiling

if __name__ == "__main__":
    ql = Qiling([r'examples/rootfs/arm_linux/bin/arm_hello'], r'examples/rootfs/arm_linux')

    # show only log entries that start with "open"
    ql.filter = '^open'
    ql.run()
```
