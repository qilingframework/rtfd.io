![Qiling Framework](img/qiling_small.png){: style="height:150px;width:150px;display:block;margin:auto"}

Qiling is an advanced binary emulation framework, with the following features:

- Cross platform: Windows, MacOS, Linux, BSD, UEFI, DOS
- Cross architecture: X86, X86_64, Arm, Arm64, MIPS, 8086
- Multiple file formats: PE, MachO, ELF, COM
- Support Linux Kernel Module(.ko) , Windows Driver(.sys) and MacOS Kernel(.kext) via [Demigod](https://groundx.io/demigod/)
- Emulates & sandbox machine code in an isolated environment
- Supports cross architecture and platform debugging capabalities
- Provides high level API to setup & configure the sandbox
- Fine-grain instrumentation: allows hooks at various levels (instruction/basic-block/memory-access/exception/syscall/IO/etc)
- Allows dynamic hotpatch on-the-fly running code, including the loaded library
- True framework in Python, making it easy to build customized security analysis tools on top

Qiling is backed by [Unicorn engine](https://www.unicorn-engine.org).

Visit our website [https://www.qiling.io](https://www.qiling.io) for more information.

---

#### License

This project is released and distributed under [free software license GPLv2](https://github.com/qilingframework/qiling/blob/master/COPYING).

---

#### Core developers

- LAU kaijern (xwings) <kj@qiling.io>
- NGUYEN Anh Quynh <aquynh@gmail.com>
- DING tianZe (D1iv3) <dddliv3@gmail.com>
- SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
- CHEN huitao (null) <null@qiling.io>
- YU tong (sp1ke) <spikeinhouse@gmail.com>
- Earl Marcus (klks84) <klks84@gmail.com> 
- WU chenxu (kabeor) <kabeor@qiling.io>
- KONG ziqiao <mio@lazym.io>

#### Travis-CI, Docker, Website and Documentation

- FOO Kevin (chfl4gs) <chfl4gs@qiling.io>
