#!/bin/sh
make -f Makefile.linux ARCH=win32 clean
make -f Makefile.linux ARCH=win32
make -f Makefile.linux ARCH=win64 clean
make -f Makefile.linux ARCH=win64
