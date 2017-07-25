#!/bin/bash
git clone https://github.com/qemu/qemu.git
cd qemu
git checkout v2.9.0
patch -p1 < ../qemu_2.9.diff

./configure --target-list=x86_64-linux-user --enable-debug
make -j4

export QEMU=x86_64-linux-user
