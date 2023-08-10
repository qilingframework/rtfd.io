---
title: Installation
---

### Overview

Qiling Framework is written in Python programming language and it works with different operating system and not limiting to any CPU architecture.

### Pre-install prep

These are my usual setup package

```
sudo apt install -y ack antlr3 aria2 asciidoc autoconf automake autopoint binutils bison build-essential \
bzip2 ccache cmake cpio curl device-tree-compiler fastjar flex gawk gettext gcc-multilib g++-multilib \
git gperf haveged help2man intltool libc6-dev-i386 libelf-dev libglib2.0-dev libgmp3-dev libltdl-dev \
libmpc-dev libmpfr-dev libncurses5-dev libncursesw5-dev libreadline-dev libssl-dev libtool lrzsz \
mkisofs msmtp nano ninja-build p7zip p7zip-full patch pkgconf python2.7 python3 python3-pip libpython3-dev qemu-utils \
rsync scons squashfs-tools subversion swig texinfo uglifyjs upx-ucl unzip vim wget xmlto xxd zlib1g-dev
```

### Pyenv Installation with latest dev branch (recommended)

If you are using pyenv, run the command shown below.

```sh
python3 -m venv qilingenv
source qilingenv/bin/activate
git clone -b dev https://github.com/qilingframework/qiling.git
cd qiling && git submodule update --init --recursive
pip3 install .
```

### pip3 install Qiling

Installation using pip (stable version)

```
pip3 install qiling
```

### pip3 install Qiling latest dev branch

To install the latest dev version using pip

```
pip3 install --user https://github.com/qilingframework/qiling/archive/dev.zip
```

### Manual Installation
For this installation guide, Ubuntu desktop latest LTS 64bit is the base example (Qiling Framework works in other Linux distributions that run Python 3.5 and above). Grab a copy of official Ubuntu ISO images from [Ubuntu CD mirrors](https://launchpad.net/ubuntu/+cdmirrors). Update and the system and also install pip3, git and cmake

```sh
sudo apt-get update
sudo apt-get upgrade
sudo apt install python3-pip git cmake
```

Once completed, clone a copy of Qiling Framework source from github and run setup to install it.

```sh
git clone https://github.com/qilingframework/qiling
cd qiling
sudo pip3 install . 
```

Also don't forget to initialize the rootfs.

```sh
git submodule update --init --recursive
```

#### Important note on Windows DLLs and registry

Due to distribution restriction, Qiling Framework will not bundle Microsoft Windows DLL files and registry. Please copy respective DLLs and registry from Microsoft Windows System. For Windows 10 usually found in C:\Windows\system32 (64bit dll) and C:\Windows\SysWOW64 (32bits dll) and place them in $rootfs/dlls

We also included a script named `dllscollector.bat`. Run this on Windows, under **Administrator** privilege, to collect all the necessary dlls and registries.

```cmd
examples/scripts/dllscollector.bat
```

Any other dlls and registry references, as below:

For 32bit Windows dlls, please refer to [DLLX86.txt](https://github.com/qilingframework/qiling/blob/master/docs/DLLX86.txt) for Windows 32bit DLLs hashes and file version

For 64bit Windows dlls, please refer to [DLLX8664.txt](https://github.com/qilingframework/qiling/blob/master/docs/DLLX8664.txt) for Windows 64bit DLLs hashes and file version

Additional Notes: .travis.yml will be able to clearly list out dlls needed

---

#### Notes on macOS >= 10.14

Keystone-engine compilation from py-pip fails (on Mojave at least) because i386 architecture is deprecated for macOS. 

```
CMake Error at /usr/local/Cellar/cmake/3.15.4/share/cmake/Modules/CMakeTestCCompiler.cmake:60 (message):
  The C compiler

    "/Library/Developer/CommandLineTools/usr/bin/cc"

  is not able to compile a simple test program.

  It fails with the following output:
```

A temporary workaround is to install keystone-engine from source:

* Install keystone-engine Python binding from source:

```sh
git clone https://github.com/keystone-engine/keystone
cd keystone
mkdir build
cd build
../make-share.sh
cd ../bindings/python
sudo make install
```

Once completed workaround installation, run Qiling Framework setup.

---

### Qiling Framework on Docker

If quick and easy way to deploy Qiling Framework is preferred, spin it with docker container.

i. Pulling the Qiling Framework docker image from dockerhub by running command below.

```sh
docker pull qilingframework/qiling:latest
```

or for Qiling Framework Docker 1.0 release.

```sh
docker pull qilingframework/qiling:1.0
```

ii. Running Qiling Framework docker with a bind mount

Required DLLs can be bind-mounted to Qiling Framework container. Presuming DLLs and HIVE files are located in sub-directories of /analysis/win/rootfs.

```sh
docker run -dt --name qiling \
 -v /analysis/win/rootfs/x86_windows:/qiling/examples/rootfs/x86_windows \
 -v /analysis/win/rootfs/x8664_windows:/qiling/examples/rootfs/x8664_windows \
 qilingframework/qiling:latest
```

Attaching to the running docker container.

```sh
docker exec -it qiling bash
```

Docker container port can be published with -p switch. This is useful for emulating service such as httpd of a router.
