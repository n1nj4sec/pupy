#!/bin/sh
./buildenv.sh
./buildenv.sh
make -f Makefile ARCH=win32 clean
make -f Makefile ARCH=win32
make -f Makefile ARCH=win64 clean
make -f Makefile ARCH=win64
