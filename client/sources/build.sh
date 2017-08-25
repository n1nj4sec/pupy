#!/bin/sh
./buildenv.sh
make -f Makefile -j ARCH=win32 clean
make -f Makefile -j ARCH=win32
make -f Makefile -j DEBUG=1 ARCH=win32 clean
make -f Makefile -j DEBUG=1 ARCH=win32
make -f Makefile -j ARCH=win32 UNCOMPRESSED=1 clean
make -f Makefile -j ARCH=win32 UNCOMPRESSED=1 
make -f Makefile -j DEBUG=1 ARCH=win32 UNCOMPRESSED=1 clean
make -f Makefile -j DEBUG=1 ARCH=win32 UNCOMPRESSED=1 
make -f Makefile -j ARCH=win64 distclean
make -f Makefile -j ARCH=win64
make -f Makefile -j DEBUG=1 ARCH=win64 clean
make -f Makefile -j DEBUG=1 ARCH=win64
make -f Makefile -j ARCH=win64 UNCOMPRESSED=1 clean
make -f Makefile -j ARCH=win64 UNCOMPRESSED=1
make -f Makefile -j DEBUG=1 ARCH=win64 UNCOMPRESSED=1 clean
make -f Makefile -j DEBUG=1 ARCH=win64 UNCOMPRESSED=1
make -f Makefile -j ARCH=win64 UNCOMPRESSED=1 distclean
