<p align="center">
<img width="150" height="150" src="https://raw.githubusercontent.com/qilingframework/qiling/master/docs/qiling_small.png">
</p>

Qiling is an advanced binary emulation framework, with the following features:

- Cross platform: Windows, MacOS, Linux, BSD, UEFI
- Cross architecture: X86, X86_64, Arm, Arm64, Mips
- Multiple file formats: PE, MachO, ELF
- Emulate & sandbox machine code in a isolated environment
- Supports cross architecture and platform debugging capabalities
- Provide high level API to setup & configure the sandbox
- Fine-grain instrumentation: allow hooks at various levels (instruction/basic-block/memory-access/exception/syscall/IO/etc)
- Allow dynamic hotpatch on-the-fly running code, including the loaded library
- True framework in Python, making it easy to build customized security analysis tools on top

Qiling is backed by [Unicorn engine](http://www.unicorn-engine.org).

Visit our website [https://www.qiling.io](https://www.qiling.io) for more information.

---

#### License

This project is released and distributed under [free software license GPLv2](COPYING).
