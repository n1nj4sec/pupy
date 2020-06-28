#!/bin/sh

SELF=$(readlink -f "$0")
SELFPWD=$(dirname "$SELF")
SRC=${SELFPWD:-$(pwd)}

cd $SRC

PUPY=$(readlink -f ../../pupy/)
TEMPLATES=$PUPY/payload_templates

EXTERNAL=../../pupy/external
PYOPUS=$EXTERNAL/pyopus/src
PIP_INSTALL="python -m pip install --upgrade"

set -e

echo "[+] Install python packages"

$PIP_INSTALL pip
$PIP_INSTALL setuptools cython
$PIP_INSTALL -q six packaging appdirs

CC=/gccwrap CFLAGS_ABORT="-D_FORTIFY_SOURCE=2 -fstack-protector" \
    $PIP_INSTALL -q pynacl --no-binary :all:

CC=/gccwrap CFLAGS_FILTER="-Wno-error=sign-conversion" \
    CFLAGS="$CFLAGS -DHEADER_UI_H -D__builtin_unreachable=abort" \
        $PIP_INSTALL -q cryptography --no-binary :all:

export PRCTL_SKIP_KERNEL_CHECK=yes

if [ "$TOOLCHAIN_ARCH" == "x86" ]; then
    export CFLAGS="$CFLAGS -D__NR_ioprio_get=290 -D__NR_ioprio_set=289"
fi

LDFLAGS="$LDFLAGS -Wl,-Bstatic -lcap -Wl,-Bdynamic" \
    $PIP_INSTALL python-prctl --no-binary :all:

$PIP_INSTALL \
    pyaml rsa netaddr==0.7.19 pyyaml ecdsa idna impacket \
    paramiko pylzma pydbus python-ptrace psutil scandir \
    scapy colorama pyOpenSSL python-xlib msgpack-python \
    u-msgpack-python poster dnslib pyxattr pylibacl http_parser \
    https://github.com/alxchk/tinyec/archive/master.zip \
    https://github.com/warner/python-ed25519/archive/master.zip \
    https://github.com/alxchk/urllib-auth/archive/master.zip \
    https://github.com/alxchk/pykcp/archive/master.zip \
    zeroconf==0.19.1 pyodbc \
    watchdog pulsectl pycryptodomex==3.7.0 --no-binary :all:

LDFLAGS="$LDFLAGS -lm -lasound" \
    $PIP_INSTALL pyalsaaudio  --no-binary :all:

if [ "$TOOLCHAIN_ARCH" == "x86" ]; then
    CFLAGS_PYJNIUS="$CFLAGS"
else
    CFLAGS_PYJNIUS="$CFLAGS -D_LP64"
fi

CFLAGS="${CFLAGS_PYJNIUS}" NO_JAVA=1 \
    python -m pip install \
    https://github.com/alxchk/pyjnius/archive/master.zip

CFLAGS="$CFLAGS -DDUK_DOUBLE_INFINITY=\"(1.0 / 0.0)\"" \
LDFLAGS="$LDFLAGS -lm" \
    $PIP_INSTALL dukpy --no-binary :all:

LDFLAGS="$LDFLAGS -lkrb5 -lk5crypto -lcom_err -lgssrpc -lgssapi_krb5" \
    $PIP_INSTALL https://github.com/alxchk/ccs-pykerberos/archive/master.zip

LDFLAGS="$LDFLAGS -lasound -lm -lrt" $PIP_INSTALL pyaudio

$PIP_INSTALL --force-reinstall pycparser==2.17

python -c 'import kcp' || exit 1

echo "[+] Compile opus"
(cd $PYOPUS && make clean && LDFLAGS="$LDFLAGS -lm" make && mv -f opus.so /usr/lib/python2.7/site-packages)
python -c 'import opus' || exit 1

echo "[+] Compile pyuv"

if [ "$TOOLCHAIN_ARCH" == "x86" ]; then
    CFLAGS_PYUV="-O2 -pipe -DCLOCK_MONOTONIC=1 -UHAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC"
    CFLAGS_PYUV="$CFLAGS_PYUV -U_FILE_OFFSET_BITS -D_XOPEN_SOURCE=600 -D__USE_XOPEN2K8"
    CFLAGS_PYUV="$CFLAGS_PYUV -D_GNU_SOURCE -DS_ISSOCK(m)='(((m) & S_IFMT) == S_IFSOCK)'"

# It may not be possible to build pyuv with linux32 toolchain, because woody don't have epoll() wrapper yet
# So make an exception
    CC=/gccwrap LDSHARED=/gccwrap \
    LDFLAGS="--shared -Os -L/opt/static -static-libgcc -Wl,--allow-shlib-undefined" \
        CFLAGS_FILTER="-D_FILE_OFFSET_BITS=64 -Wl,--no-undefined" CFLAGS="$CFLAGS_PYUV" \
        $PIP_INSTALL https://github.com/alxchk/pyuv/archive/v1.x.zip --no-binary :all:
else
    CFLAGS="$CFLAGS -D_XOPEN_SOURCE=600 -D_GNU_SOURCE -DS_ISSOCK(m)='(((m) & S_IFMT) == S_IFSOCK)'" \
        $PIP_INSTALL https://github.com/alxchk/pyuv/archive/v1.x.zip --no-binary :all:
fi

# $PIP_INSTALL --no-binary :all: pycryptodome==3.7.0
$PIP_INSTALL --no-binary :all: https://github.com/Legrandin/pycryptodome/archive/master.zip

cd /usr/lib/python2.7

echo "[+] Strip python modules"
find -name "*.so" | while read f; do strip $f; done

echo "[+] Build python template ($TOOLCHAIN_ARCH)"

rm -f ${TEMPLATES}/linux-${TOOLCHAIN_ARCH}.zip
zip -y -r -9 ${TEMPLATES}/linux-${TOOLCHAIN_ARCH}.zip . \
    -x "*.a" -x "*.la" -x "*.o" -x "*.whl" -x "*.txt" -x "*.pyo" -x "*.pyc" \
    -x "*test/*" -x "*tests/*" -x "*examples/*" \
    -x "*.egg-info/*" -x "*.dist-info/*" \
    -x "idlelib/*" -x "lib-tk/*" -x "tk*" -x "tcl*" >/dev/null

cd /usr/lib
zip -9 ${TEMPLATES}/linux-${TOOLCHAIN_ARCH}.zip \
    libpq.so libodbc.so psqlodbcw.so libodbcinst.so libmaodbc.so

ldconfig

echo "[+] Build pupy"

case $TOOLCHAIN_ARCH in
amd64)
    MAKEFLAGS="ARCH=64 MACH=x86_64"
    TARGETS="pupyx64d.lin pupyx64d.lin"
    TARGETS="$TARGETS pupyx64.lin pupyx64.lin.so"
    ;;

x86)
    MAKEFLAGS="ARCH=32 PIE= MACH=i686"
    TARGETS="pupyx86d.lin pupyx86d.lin.so"
    TARGTS="$TARGETS pupyx86.lin pupyx86.lin.so"
    ;;

*)
    LIBS="LIBSSL=/usr/lib/libssl.so LIBCRYPTO=/usr/lib/libcrypto.so"
    LIBS="$LIBS LIBPYTHON=/usr/lib/libpython2.7.so"
    MAKEFLAGS="MACH=${TOOLCHAIN_ARCH} $LIBS"
    TARGETS="pupy${TOOLCHAIN_ARCH}d.lin pupy${TOOLCHAIN_ARCH}d.lin.so"
    TARGTS="$TARGETS pupy${TOOLCHAIN_ARCH}.lin pupy${TOOLCHAIN_ARCH}.lin.so"
    ;;
esac

for target in $TARGETS; do rm -f $TEMPLATES/$target; done

cd $SRC

MAKEFLAGS="$MAKEFLAGS OPENSSL_LIB_VERSION=1.1"

make $MAKEFLAGS distclean
make -j $MAKEFLAGS
make $MAKEFLAGS clean
make -j DEBUG=1 $MAKEFLAGS

for object in $TARGETS; do
    if [ -z "$object" ]; then
        continue
    fi

    if [ ! -f $TEMPLATES/$object ]; then
        echo "[-] $object - failed"
        FAILED=1
    fi
done

if [ -z "$FAILED" ]; then
    echo "[+] Build complete"
else
    echo "[-] Build failed"
    exit 1
fi
