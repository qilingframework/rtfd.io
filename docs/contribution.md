---
title: Contribution Guide
---

## Introduction

Qiling Framework is always a fast-evolving project, thanks to the efforts of the whole community. Since more and more developers join us, it's also a big challenge to maintain the whole project clean and thus here comes the contribution guide.

Before creating your first pull request, please read this page carefully.

## Join us

- Join our [telegram group](https://t.me/qilingframework), most of our developers are active in this group.
- Follow our twitter [@qiling_io](https://twitter.com/qiling_io) to get latest news.
- We also have a QQ group: 486812017.
- Don't forget to give us a star on [Github](https://github.com/qilingframework/qiling)!

## Check existing issue/PR

Before submitting your pull request, please search in issues and PRs firstly. Also remember to check our [TODO](https://github.com/qilingframework/qiling/issues/333) and [FAQ](https://docs.qiling.io/en/latest/faq/).

## Reading materials

Before starting your first line, there are a bunch of reading materials for you to get start.

See [here](https://github.com/qilingframework/qiling/issues/134) for a full list.

## Based on dev and merge to dev

Once you fork our project and decide to write your awesome PR, one thing you should keep in mind is that: Always work on dev branch.

In Qiling Framework, dev branch means new features, new fixes and testing functions where new pull requests should be based on.

## Coding Convention

!!! note
    Since the refactor is going on, you may find some parts of current codebase are opposite to these conventions.

### Logging

`ql.nprint` and `ql.dprint` is **being depreciated** and will be removed in a future release. Please use python `logging` module directly.

```python
# ql.dprint(D_INFO, "A debug message")
logging.debug("A debug message")
# ql.nprint("An info message")
logging.info("An info message")
```

When catching an exception, besides simply raising it, `logging.exception` can be of great help.

```python
try:
    1/0
except ZeroDivisionError as e:
    #print(e)
    logging.exception("Divide by zero!")
```

### Property

Whenever you would like to add a class member, consider property instead.

```python
class QlOsDumb:
    def __init__(self):
        #self.dumb = 1
        self._dumb = 1
    
    @property
    def dumb(self):
        return self._dumb

    def do_something(self):
        print(self.dumb)
```

Python property is more readable and helpful for code autocompletion.

### Type hinting

Python [type hinting](https://docs.python.org/3/library/typing.html) is a kind of **edit-time** annotation which provides extra information for autocompletion.

```python
def ql_is_multithread(ql: Qiling) -> bool:
    return ql.multithread
```

!!! note
    Due to the historical design problem, you may encounter cyclic import when adding type hints. See [this link](https://stackoverflow.com/questions/39740632/python-type-hinting-without-cyclic-imports) for a clean solution.

### Docstring

Whenever possible, add docstring for your method or property.

```python
def ql_dumb_function():
    ```
    This is a docstring
    ```
    pass
```

### Naming

See codes below for naming convention.

```python
# Class: PascalCase
class QlOsDumb:
    pass

# Function: snake_case
def ql_dumb_function():
    pass

# Variable: snake_case
mem_ptr = 0

# Constants: UPPERCASE
# If the constant is from other place, e.g. Linux Kernel, follow their naming convention.
ERROR = 0
```

### Tests

If your PR consists of some new features, remember to add a new test.

See [test_pathutils.py](https://github.com/qilingframework/qiling/blob/dev/tests/test_pathutils.py) for an example.

### Imports

Always prefer relative imports for qiling modules.

```python
from .mapper import QlFsMapper
```

Built in modules should be imported either in one line or fully seperately.

```python
# ok
import logging, os, re
# ok
import logging
import re
import os
# no
import logging, re
import os
```

!!! note
    Due to the historical design problem on project structure, you may have to use full import like `from qiling.os.utils import *` sometimes.

### Comments

You should leave comments for your code if it matches the following cases:

- This part of code is copied/rewritten/extracted from other location, e.g. Linux kernel, etc.
- This implementation follows some external documents, e.g. Linux manual.
- This code has some unexpected side effects.

Of course, the more, the better.

## Changelog

Finally, before merging your PR into dev branch, one last thing you have to do is to update [Changelog](https://github.com/qilingframework/qiling/issues/134).