#!/bin/sh

SELF=$(readlink -f "$0")
SELFPWD=$(dirname "$SELF")
SRC=${SELFPWD:-$(pwd)}

cd $SRC

PUPY=$(readlink -f ../../pupy/)
TEMPLATES=$PUPY/payload_templates

EXTERNAL=../../pupy/external
PYKCP=$EXTERNAL/pykcp
PYOPUS=$EXTERNAL/pyopus/src
SUFFIX="-`python -c 'import sys;sys.stdout.write((chr.__call__(0)[0:0]).join([str(x) for x in sys.version_info[0:2]]));sys.stdout.flush()'`"
PIP_INSTALL="python -m pip install --upgrade"


set -e

echo "[+] Install python packages"

$PIP_INSTALL pip
$PIP_INSTALL setuptools cython
$PIP_INSTALL -q six packaging appdirs
#CC=/gccwrap

CFLAGS_ABORT="-D_FORTIFY_SOURCE=2 -fstack-protector" \
    $PIP_INSTALL -q pynacl

CFLAGS_FILTER="-Wno-error=sign-conversion" \
    CFLAGS="$CFLAGS -DHEADER_UI_H -D__builtin_unreachable=abort" \
        $PIP_INSTALL -q cryptography --no-binary :all:

export PRCTL_SKIP_KERNEL_CHECK=yes

if [ "$TOOLCHAIN_ARCH" = "x86" ]; then
    export CFLAGS="$CFLAGS -D__NR_ioprio_get=290 -D__NR_ioprio_set=289"
fi
LDFLAGS="$LDFLAGS -Wl,-Bstatic -lcap -Wl,-Bdynamic" \
    $PIP_INSTALL python-prctl

$PIP_INSTALL pyodbc
$PIP_INSTALL \
    pyaml ushlex rsa netaddr pyyaml ecdsa idna impacket \
    paramiko pylzma pydbus python-ptrace psutil scandir \
    scapy colorama pyOpenSSL python-xlib msgpack-python \
    u-msgpack-python dnslib pyxattr pylibacl http_parser \
    https://github.com/alxchk/tinyec/archive/master.zip \
    https://github.com/warner/python-ed25519/archive/master.zip \
    https://github.com/alxchk/urllib-auth/archive/master.zip \
    zeroconf \
    watchdog pulsectl pycryptodomex --no-binary :all:

LDFLAGS="$LDFLAGS -lm -lasound" CFLAGS="$CFLAGS -std=gnu99" \
    $PIP_INSTALL pyalsaaudio  --no-binary :all:

if [ "$TOOLCHAIN_ARCH" = "x86" ]; then
    CFLAGS_PYJNIUS="$CFLAGS"
else
    CFLAGS_PYJNIUS="$CFLAGS -D_LP64"
fi

#CFLAGS="${CFLAGS_PYJNIUS}" NO_JAVA=1 \
#    python -m pip install \
#    https://github.com/alxchk/pyjnius/archive/master.zip

CFLAGS="$CFLAGS -DDUK_DOUBLE_INFINITY=\"(1.0 / 0.0)\"" \
LDFLAGS="$LDFLAGS -lm" \
    $PIP_INSTALL dukpy --no-binary :all:

#LDFLAGS="$LDFLAGS -lkrb5 -lk5crypto -lcom_err -lgssrpc -lgssapi_krb5" \
#    $PIP_INSTALL https://github.com/alxchk/ccs-pykerberos/archive/master.zip
LDFLAGS="$LDFLAGS -lasound -lm -lrt" $PIP_INSTALL pyaudio

$PIP_INSTALL --force-reinstall pycparser==2.17

echo "[+] Compile pykcp"
rm -rf $PYKCP/{kcp.so,kcp.pyd,kcp.dll,build,KCP.egg-info}
$PIP_INSTALL --force $PYKCP
python -c 'import kcp' || exit 1

#echo "[+] Compile opus"
#(cd $PYOPUS && make clean && LDFLAGS="$LDFLAGS -lm" make && mv -f opus.so /usr/lib/python2.7/site-packages)
#python -c 'import opus' || exit 1

echo "[+] Compile pyuv"

if [ "$TOOLCHAIN_ARCH" = "x86" ]; then
    CFLAGS_PYUV="-O2 -pipe -DCLOCK_MONOTONIC=1 -UHAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC"
    CFLAGS_PYUV="$CFLAGS_PYUV -U_FILE_OFFSET_BITS -D_XOPEN_SOURCE=600 -D__USE_XOPEN2K8"
    CFLAGS_PYUV="$CFLAGS_PYUV -D_GNU_SOURCE -DS_ISSOCK(m)='(((m) & S_IFMT) == S_IFSOCK)'"

# It may not be possible to build pyuv with linux32 toolchain, because woody don't have epoll() wrapper yet
# So make an exception
    LDFLAGS="--shared -Os -L/opt/static -static-libgcc -Wl,--allow-shlib-undefined" \
        CFLAGS_FILTER="-D_FILE_OFFSET_BITS=64 -Wl,--no-undefined" CFLAGS="$CFLAGS_PYUV" \
        $PIP_INSTALL https://github.com/alxchk/pyuv/archive/v1.x.zip --no-binary :all:
else
    CFLAGS="$CFLAGS -D_XOPEN_SOURCE=600 -D_GNU_SOURCE -DS_ISSOCK(m)='(((m) & S_IFMT) == S_IFSOCK)'" \
        $PIP_INSTALL https://github.com/alxchk/pyuv/archive/v1.x.zip --no-binary :all:
fi

#$PIP_INSTALL --no-binary :all: pycryptodome
$PIP_INSTALL https://github.com/Legrandin/pycryptodome/archive/master.zip

#cd /usr/lib/python3.10
cd ~/.pyenv/versions/3.*/lib/python3.*

echo "[+] Strip python modules"
find -name "*.so" | while read f; do strip $f; done

echo "[+] Build python template ($TOOLCHAIN_ARCH)"

rm -f ${TEMPLATES}/linux-${TOOLCHAIN_ARCH}${SUFFIX}.zip
zip -y -r -9 ${TEMPLATES}/linux-${TOOLCHAIN_ARCH}${SUFFIX}.zip . \
    -x "*.a" -x "*.la" -x "*.o" -x "*.whl" -x "*.txt" -x "*.pyo" -x "*.pyc" \
    -x "*test/*" -x "*tests/*" -x "*examples/*" \
    -x "*.egg-info/*" -x "*.dist-info/*" \
    -x "idlelib/*" -x "lib-tk/*" -x "tk*" -x "tcl*" >/dev/null

#cd /usr/lib
mkdir -p /tmp/libs
cd /tmp/libs
cp /usr/lib/x86_64-linux-gnu/libodbc.so.1 libodbc.so

zip -9 ${TEMPLATES}/linux-${TOOLCHAIN_ARCH}${SUFFIX}.zip \
    libpq.so libodbc.so psqlodbcw.so libodbcinst.so libmaodbc.so

echo "[+] Build pupy"

case $TOOLCHAIN_ARCH in
amd64)
    MAKEFLAGS="ARCH=64 MACH=x86_64"
    TARGETS="pupyx64d${SUFFIX}.lin pupyx64d${SUFFIX}.lin"
    TARGETS="$TARGETS pupyx64${SUFFIX}.lin pupyx64${SUFFIX}.lin.so"
    export LIBPYTHON=/root/.pyenv/versions/3.10.6/lib/libpython3.10.so
    export LIBPYTHON_INC="-I/root/.pyenv/versions/3.10.6/include/python3.10"
    ;;

x86)
    MAKEFLAGS="ARCH=32 PIE= MACH=i686 $LIBS"
    TARGETS="pupyx86d${SUFFIX}.lin pupyx86d${SUFFIX}.lin.so"
    TARGETS="$TARGETS pupyx86${SUFFIX}.lin pupyx86${SUFFIX}.lin.so"
    ;;

*)
    LIBS="LIBSSL=/usr/lib/libssl.so LIBCRYPTO=/usr/lib/libcrypto.so"
    LIBS="$LIBS LIBPYTHON=/usr/lib/libpython3.10.so"
    MAKEFLAGS="MACH=${TOOLCHAIN_ARCH} $LIBS"
    TARGETS="pupy${TOOLCHAIN_ARCH}d.lin pupy${TOOLCHAIN_ARCH}d.lin.so"
    TARGETS="$TARGETS pupy${TOOLCHAIN_ARCH}${SUFFIX}.lin pupy${TOOLCHAIN_ARCH}${SUFFIX}.lin.so"
    ;;
esac

for target in $TARGETS; do rm -f $TEMPLATES/$target; done

cd $SRC

MAKEFLAGS="$MAKEFLAGS OPENSSL_LIB_VERSION=1.1"

export PKG_CONFIG_PATH=$(echo ~/.pyenv/versions/*/lib/pkgconfig)

make $MAKEFLAGS distclean
make -j $MAKEFLAGS
#make $MAKEFLAGS
make $MAKEFLAGS clean
make -j DEBUG=1 $MAKEFLAGS
#make DEBUG=1 $MAKEFLAGS

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
