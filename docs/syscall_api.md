---
title: How to add syscall or operating system API into Qiling Framework
---

Due to the nature of Qiling Framework design, operational system API and posix syscalls will always be lacking behind real kernel. We covered around 40% of Windows API and Linux based syscall and unknown coverage on UEFI. This will be a continuous and never-ending job and help from community is highly appreciated. We hope for more contributors in helping on API or syscall implementation, either adding or maintaining them.

Our job is to make syscall or API as close to kernel as possible. But there are times, we just do not follow them 100%. For example, pid, uid, mprotect related syscall are just a quick feedback and write into a appropriate register.

### Posix syscall
We split the posix/syscall.py file into multiple files in posix/syscall directory. Seperation of syscall should follow its header, which is defined in the syscall function. 

For example, syscall setpriority is defined in resource.h, ql_syscall_setpriority should be in syscall/resource.py. ql_syscall_clock_gettime should be in syscall/time.py.

### Operating System API (Windows or UEFI)
This is applicable to operational API as well, the header file will be the guideline how we can split the API into different files.

### How to start
Before writing an API or syscall, user can always try ql.set_api or ql.set_syscall. Please see [Hijack](https://docs.qiling.io/en/latest/hijack/). This will be a very simple way to test out customized syscall or API before modifying the core source codes.

### Contributing
After adding syscall into core. Please make sure edit qiling/os/linux/<arch>.py to match the syscall function and syscall number.

API mapping is being done in ql.hook_code. 
