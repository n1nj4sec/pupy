#!/usr/bin/bash

set -e

exec 2>buildenv-sunos.log

BUILDENV=`pwd`/buildenv-sunos
TEMPLATES=`pwd`/../../pupy/payload_templates

mkdir -p $BUILDENV

# VERSIONS /MAY/ BE UPDATED (In case of vulnerabilites)
OPENSSL_SRC="http://http.debian.net/debian/pool/main/o/openssl/openssl_1.0.2k.orig.tar.gz"
ZLIB_SRC="http://zlib.net/zlib-1.2.11.tar.gz"
SQLITE_SRC="http://www.sqlite.org/2016/sqlite-autoconf-3150200.tar.gz"
LIBFFI_SRC="http://http.debian.net/debian/pool/main/libf/libffi/libffi_3.2.1.orig.tar.gz"
PYTHON_SRC="https://www.python.org/ftp/python/2.7.13/Python-2.7.13.tgz"

export PATH="$BUILDENV/build/bin:/opt/csw/bin/:/usr/sfw/bin/:/usr/xpg4/bin/:$PATH"

# pkgutil -y -i wget automake autoconf pkgconfig xz libtool git

if [ ! -d $BUILDENV/src ]; then
    mkdir -p $BUILDENV/build $BUILDENV/src
    cd $BUILDENV/src
    for bin in "$OPENSSL_SRC" "$ZLIB_SRC" "$SQLITE_SRC" "$LIBFFI_SRC" "$PYTHON_SRC"; do
        wget -O - "$bin" | gzip -d | tar xf -
    done
    cd -
fi

export LD_LIBRARY_PATH=$BUILDENV/build/lib
export CFLAGS="-m64 -fPIC -DSUNOS_NO_IFADDRS -DHAVE_AS_X86_64_UNWIND_SECTION_TYPE -I$BUILDENV/build/lib/libffi-3.2.1/include -I$BUILDENV/build/include"
export LDFLAGS="-m64 -fPIC -L$BUILDENV/build/lib"
export PKG_CONFIG_PATH="$BUILDENV/build/lib/pkgconfig"
set -x

ln -sf /usr/lib/amd64/libcrypt_i.so /usr/lib/amd64/libcrypt.so

cd $BUILDENV/src/zlib-1.2.11
./configure --64 --static --prefix=$BUILDENV/build; gmake; gmake install

cd $BUILDENV/src/libffi-3.2.1
./configure --enable-static --disable-shared --prefix=$BUILDENV/build; make; make install

cd $BUILDENV/src/sqlite-autoconf-3150200
./configure --enable-static --disable-shared --prefix=$BUILDENV/build; gmake; gmake install

cd $BUILDENV/src/openssl-1.0.2k
./Configure --openssldir=$BUILDENV/build/ shared solaris64-x86_64-gcc; gmake; gmake install

cd $BUILDENV/src/Python-2.7.13
./configure --with-ensurepip=install --enable-unicode=ucs4 --with-system-ffi --enable-ipv6 --enable-shared --prefix=$BUILDENV/build
gmake; gmake install

python -OO -m pip install git+https://github.com/alxchk/psutil.git
python -OO -m pip install six packaging appdirs
python -OO -m pip install \
       rpyc pycrypto pyaml rsa netaddr tinyec pyyaml ecdsa \
       paramiko uptime pylzma pydbus python-ptrace scandir \
       scapy colorama pyOpenSSL \
       --upgrade --no-binary :all:

export LDFLAGS="$LDFLAGS -lsendfile -lkstat"
python -OO -m pip install git+https://github.com/alxchk/pyuv.git

cd $BUILDENV/build/lib/python2.7

python -OO -m compileall -q . || true

zip -y \
    -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.py" -x "*.pyo" \
    -x "*test/*" -x "*tests/*" -x "*examples/*" \
    -r9 ${TEMPLATES}/solaris-`uname -m`.zip .


