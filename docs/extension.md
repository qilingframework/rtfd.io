---
title: How to add Loader, Architecture or Operating System into Qiling Framework
---

There are 3 major pats in Qiling Framework.

### Loader
This parts should contain:

- File identifier: which os, which arch
- Loader itself
- Mapping for shellcode. The the OS support shellcode
- stack, memory and heap setup
- ENV setup
- ARGV setup

- Related files: 
> - qiling/utils.py
> - qiling/const.py
> - qiling/loader/<loader>.py

### Arch
This parts should contain all the function or CPU feature soon needs to be configure during OS initialization.

- setup VFP
- very specific arch functions, such as GS/FS and etc
- init_tls settings

- Related files:
> - qiling/arch/<arch>.py

### Operating System
Only two parts, initialized and run. OS initialization should contain:

- CPU setup
- OS related components, such as 
> - output 
> - stdio 
> - registry
> - thread management
> - API or syscall mapping, [read here](https://docs.qiling.io/en/latest/syscall_api/)

- Related files:
> - qiling/os/<os>.py
