---
title: Qiling debugger
---
### Introduction

This plugin is a modified version from [Qdb](https://github.com/ucgJhe/Qdb)

### Features

1. commandline-based user interface

![](img/qdb_cmd_start.png)

2. step-by-step execution

- use command `step` or `s` to execute one instruction at a time

![](img/qdb_step.png)

3. breakpoints

- use command `breakpoint` or `b` to setup a breakpoint, and continue execution with `continue` or `c`

![](img/qdb_breakpoint.png)

4. dynamic memory examination

- use command `examine` or `x` to read data from memory

![](img/qdb_mem_examination.png)

5. record and replay

- use command `backward` or `p` to step backward from current location
- Note:
    - 1. the address you want to step backward on it must be step-over before 
    - 2. make sure run qdb with option `rr=True`

![](img/qdb_step_backward.png)
