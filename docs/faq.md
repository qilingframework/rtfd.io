---
title: FAQ
---

### Keystone Engine Installation Error
- This is a known issue and we are working with Keystone Engine to fix this. You can safely ignore Keystone engine installation error as Qiling Framework will work without Keystone Engine, unless you call ql.compile().

### Keystone Module Not Found
- There is a workaround for this issue. But you can always swtich to dev branch.

### How to swtich to dev branch
```
git clone https://github.com/qilingframework/qiling.git
git checkout dev
```

### My program crashes. It says Syscall/API not implemented
- Most likely the syscall or OS api required by the binary is not implemented. You might want to write the syscall or OS api and contribute to the project. But in some cases, the syscall (maybe only syscall) is not being mapped to the arch. Map the syscall to the arch will always work.
- Some cases like [issue 281](https://github.com/qilingframework/qiling/issues/281) we can reuse similar syscall. For example, vfork and fork can be shared most of the time. Always remember, Qiling is a emulator, some of the syscall do not have to be 100% identical to a real kernel.

### Windows API often comes with functionsA and functionW. Do I need to implement both?
- Thanks to [jhumble](https://github.com/jhumble), he implemented wraps from functools to make A and W combile, please refer to [pull request 261](https://github.com/qilingframework/qiling/pull/261).

### UC_ERR_FETCH_UNMAPPED, UC_ERR_WRITE_UNMAPPED and related issues
- This is not a "bug". There are possibily few major causes for this error

1. Windows API or syscall not being implemented
> - Qiling Framework tries to emulate various platforms such as Linux, MacOS, Windows, FreeBSD and UEFI. All these platforms come with different archnitecture. Its not possible for Qiling Framework to be able to emulate all these syscall/API. Community help is needed.

2. Some specific requiremment needed.
> - Firmware might need interface br0 and a users testing enviroment might not have it. In this case, ql.patch will come in handy.

3. Required some missing files
> - Missing conifig file or library can cause the targeted binary fail to run properly.

It is adviseble to always turn on debugging or disassambly mode to pintpoint the issue and try to resolve it. Technically, this is not a bug but rather a feature.
