#!/bin/sh
./buildenv.sh
./buildenv.sh
make -f Makefile ARCH=win32 clean
make -f Makefile ARCH=win32
make -f Makefile DEBUG=1 ARCH=win32 clean
make -f Makefile DEBUG=1 ARCH=win32
make -f Makefile ARCH=win64 clean
make -f Makefile ARCH=win64
make -f Makefile DEBUG=1 ARCH=win64 clean
make -f Makefile DEBUG=1 ARCH=win64
