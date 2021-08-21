---
title: Custom Engine
---

### How to install Qiling Framework custom Engine module
```
git clone https://github.com/qilingframework/qiling.git
git checkout dev
git submodule update --init
pip3 install -e .[evm]
```

### How to test EVM modules
```
cd tests
pyton3 ./test_evm.py
```

### Examples?
yes, refer to our [github repo](https://github.com/qilingframework/qiling/tree/dev/qiling/examples/evm)