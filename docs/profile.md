---
title: Profile
---

Thre is a Qiling Frameworks default profile, custom user profile will override default profile value.

```python
from qiling import *

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output="debug", profile= "netgear.ql")
    ql.add_fs_mapper("/proc", "/proc")
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/netgear_r6220/bin/mini_httpd","-d","/www","-r","NETGEAR R6220","-c","**.cgi","-t","300"], "rootfs/netgear_r6220")
```

content of netgear.ql
```
[MIPS]
mmap_address = 0x7f7ee000
log_dir = qlog
log_split = True
```

Default profile for different OSes:

- Windows: [qiling/pofiles/windows.ql](https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/windows.ql)
- Linux: [qiling/pofiles/linux.ql](https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/linux.ql)
- MacOS: [qiling/pofiles/macos.ql](https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/macos.ql)
- UEFI: [qiling/pofiles/uefi.ql](https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/uefi.ql)
- UEFI: [qiling/pofiles/freebsd.ql](https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/freebsd.ql)
