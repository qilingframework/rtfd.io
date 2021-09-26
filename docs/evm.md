---
title: EVM Engine
---

### How to install Qiling Framework custom Engine module
```bash
git clone https://github.com/qilingframework/qiling.git
git checkout dev
git submodule update --init
pip3 install -e .[evm]
```

### How to test EVM modules
```bash
cd tests
python3 ./test_evm.py
```

### Examples?
yes, refer to our [github repo](https://github.com/qilingframework/qiling/tree/dev/examples/evm)


### Executing a EVM Smart Contract Bytecode
```python
import sys
from qiling import *

if __name__ == '__main__':
    ql = Qiling(archtype="evm")
    contract = "0x60606040..."                               # Smart Contract Bytecode

    bal = ql.arch.evm.abi.convert(['uint256'], [20])         
    contract = contract + bal                                # add Bytecode init parameters(Optional)

    user1 = ql.arch.evm.create_account(balance=100*10**18)   # Creating a user account with 100 ETH
    c1 = ql.arch.evm.create_account()                        # Creating a contract account

    call_data = '0x...'                                      # Function Sign and parameters
    msg1 = ql.arch.evm.create_message(user1, c1, call_data)  # Creating a transaction message
    result = ql.run(code=msg1)                               # Running this transaction
```


### Debugging a EVM Smart Contract Bytecode
```python
import sys
from qiling import *

if __name__ == '__main__':
    ql = Qiling(archtype="evm")
    ql.debugger = True                                       # Just need turn ql.debugger = True, you will see Debugger GUI in terminal
    contract = "0x60606040..."                               # Smart Contract Bytecode

    user1 = ql.arch.evm.create_account(balance=100*10**18)
    c1 = ql.arch.evm.create_account()

    msg0 = ql.arch.evm.create_message(user1, b'', code=contract, contract_address=c1)
    ql.run(code=msg0)
```


### Setting a special hard fork
```python
from .vm.evm import QlArchEVMEmulator
from qiling.arch.evm.constants import BERLIN_FORK

if __name__ == '__main__':
    ql = Qiling(archtype="evm")
    ql.arch.evm = QlArchEVMEmulator(self.ql, fork_name=BERLIN_FORK)  # Setting new fork name here

    ...
```


### What is Smart Contract?
**Note that if you don't know enough about smart contracts, please visit the links provided below.**

- [What is EVM?](https://ethereum.org/en/developers/docs/evm/)
- [Remix IDE for EVM Smart Contract](https://remix.ethereum.org/)