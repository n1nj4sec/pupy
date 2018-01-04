#!/usr/bin/bash

# ./buildenv-sunos.sh || exit 1

export BUILDENV=`pwd`/buildenv-sunos
export LD_LIBRARY_PATH="$BUILDENV/build/lib"
export PATH="$BUILDENV/build/bin:/opt/csw/bin/:/usr/sfw/bin/:/usr/xpg4/bin/:/usr/sfw/i386-sun-solaris2.10/bin/:$PATH"
export PKG_CONFIG_PATH="$BUILDENV/build/lib/pkgconfig"

gmake clean
gmake \
    CC=gcc \
    ARCH=64 \
    LIBPYTHON=$BUILDENV/build/lib/libpython2.7.so.1.0 \
    LIBCRYPTO=$BUILDENV/build/lib/libcrypto.so.1.0.0 \
    LIBSSL=$BUILDENV/build/lib/libssl.so.1.0.0
gmake clean
gmake \
    CC=gcc \
    ARCH=64 \
    LIBPYTHON=$BUILDENV/build/lib/libpython2.7.so.1.0 \
    LIBCRYPTO=$BUILDENV/build/lib/libcrypto.so.1.0.0 \
    LIBSSL=$BUILDENV/build/lib/libssl.so.1.0.0 \
    DEBUG=1
