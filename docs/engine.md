---
title: Custom Engine
---

### How to install Qiling Framework custom Engine module
```
git clone https://github.com/qilingframework/qiling.git
git submodule update --init
pip3 install -e .[evm]
```

### How to test EVM modules
```
cd qiling/engine/test
pyton3 ./test_evm.py
```

### Examples?
yes, refer to our [github repo](https://github.com/qilingframework/engine/tree/main/examples)