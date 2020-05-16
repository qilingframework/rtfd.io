---
title: How to add syscall or operating system api into Qiling Framework
---

Due to the nature of Qiling design. We are always lack of operation system API and posix syscall.

We always hope for more contribors to help on API or syscall implementation. Either to add or to maintain it.

We covered around 40% of Windows API and Linux based syscall and not too sure about UEFI. This will be a never ending jon and help from community is appriciated.

Our job is to make syscall or api as close to kernel as possible. But there are times we just don't have to follow 100%. For example, pid, uid, mprotect realted stscall are just a quick feedback and write into a appropiate register.

### Posix syscall
We split the posix/syscall.py file into multiple files in posix/syscall dir. Speration of  syscall should follow its header, which define in the syscall fucntion. 

For example, syscall setpriority is defined in resource.h, ql_syscall_setpriority should be in syscall/resource.py. ql_syscall_clock_gettime should be in syscall/time.py.

### Operating System API (Windows or UEFI)
Same goes to openration api, the header file will be the guide line how we can split the API into differnt file

### How to start
Before writing a API or syscall, user can always try ql.set_api or ql.set_syscall (https://docs.qiling.io/en/latest/hijack/) this will be a very simple way to test your customized syscall or API before touching the code in core

### Contributing
After adding syscall into core. Please make sure edit qiling/os/linux/<arch>.py to match the syscall function and syscall number.

Api mapping is being done in ql.hool_code. 

