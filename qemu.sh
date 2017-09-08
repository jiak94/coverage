#!/bin/bash
git clone https://github.com/qemu/qemu.git
cd qemu
git checkout v2.9.0
patch -p1 < ../qemu_patch.diff

./configure --target-list=x86_64-linux-user --enable-debug
make -j4

