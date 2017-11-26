#!/bin/sh
if [ -z "$UID" ]; then
    UID=`id -u`
fi

if [ ! $UID -eq 0 ]; then
    echo "[!] You need to be root to run this script"
    su -c ./$0 "$1"
    exit
fi

if [ ! -d "${PUPY_DIR}" ]; then
    echo "Usage: $0 "
fi

mount --bind ../../ buildenv/lin32/mnt
mount -t proc proc buildenv/lin32/proc
mount -t devtmpfs devtmpfs buildenv/lin32/dev

cat << __CMDS__ | chroot buildenv/lin32 /bin/bash
su - pupy
export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin:/usr/local/sbin
cd /mnt/client/sources-linux
make clean
make -j PIE=
make clean
make -j DEBUG=1 PIE=
make clean
make -j PIE= UNCOMPRESSED=1
make clean
make -j DEBUG=1 PIE= UNCOMPRESSED=1
make distclean
__CMDS__

umount buildenv/lin32/dev
umount buildenv/lin32/proc
umount buildenv/lin32/mnt


mount --bind ../../ buildenv/lin64/mnt
mount -t proc proc buildenv/lin64/proc
mount -t devtmpfs devtmpfs buildenv/lin64/dev

cat << __CMDS__ | chroot buildenv/lin64 /bin/bash
su - pupy
export PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin:/usr/local/sbin
cd /mnt/client/sources-linux
make clean
make -j
make clean
make -j DEBUG=1
make clean
make -j UNCOMPRESSED=1
make clean
make -j DEBUG=1 UNCOMPRESSED=1
make distclean
__CMDS__

umount buildenv/lin64/dev
umount buildenv/lin64/proc
umount buildenv/lin64/mnt
