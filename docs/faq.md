---
title: FAQ
---

### Keystone Engine Installation Error
- Yes, we are working with Keystone Engine to fix this issue and you can ignore Keystone engine installation error. Qiling Framework will work without Keystone Engine, unless you call ql.compile().

### My program crash it says Syscall/API not implemented
- Very high possibality the syscall or OS api required by the binary is not implemented. You might want to write the syscall or OS api, but in some cases the syscall(maybe only syscall) is not being mapped to the arch. Map the syscall to the arch will always work.
- Some cases like [issue 281](https://github.com/qilingframework/qiling/issues/281) we can reuse similar syscall. For example vfork and fork can be share most of the time. Always remember Qiling is a emulator, some of the syscall dont have to be 100% identical to a real kernel

### Windows API often comes with functionsA and functionW do i need to implement both
- Thanks for jhumble, he implemented wraps from functools to make A and W combile, please refer to [pull reuquest 261]https://github.com/qilingframework/qiling/pull/261
