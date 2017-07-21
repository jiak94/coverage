#!/bin/bash
git clone https://github.com/qemu/qemu.git
cd qemu
git checkout v2.1.3
patch -p1 < ../myqemu.diff

./configure --target-list=x86_64-linux-user --enable-debug
make -j4

export QEMU=x86_64-linux-user
