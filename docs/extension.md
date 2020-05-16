---
title: How to add Loader, Architecture or Operating System into Qiling Framework
---

There are 3 major components in Qiling Framework.

### Loader
This part should contain:

- File identifier: which os, which arch
- Loader itself
- Mapping for shellcode. The OS supported shellcode
- stack, memory and heap setup
- ENV setup
- ARGV setup

- Related files: 
> - qiling/utils.py
> - qiling/const.py
> - qiling/loader/<loader>.py

### Arch
This part should contain all the functions or CPU features needed to be configured during OS initialization.

- set up VFP
- very specific arch functions, such as GS/FS and etc
- init_tls settings

- Related files:
> - qiling/arch/<arch>.py

### Operating System
There are 2 stages in this part, initialize and run. OS initialization should contain:

- CPU setup
- OS related components, such as 
> - output 
> - stdio 
> - registry
> - thread management
> - API or syscall mapping, [read here](https://docs.qiling.io/en/latest/syscall_api/)

- Related files:
> - qiling/os/<os>.py
