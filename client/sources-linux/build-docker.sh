#!/bin/sh

SELF=`readlink -f "$0"`
SELFPWD=`dirname "$SELF"`
SRC=${SELFPWD:-`pwd`}

cd $SRC

PUPY=`readlink -f ../../pupy/`
TEMPLATES=$PUPY/payload_templates

EXTERNAL=../../pupy/external
PYKCP=$EXTERNAL/pykcp
PYOPUS=$EXTERNAL/pyopus/src

set -e

echo "[+] Install python packages"

python -m pip install --upgrade pip
python -m pip install --upgrade setuptools
python -m pip install --upgrade -q six packaging appdirs

CC=/gccwrap CFLAGS_ABORT="-D_FORTIFY_SOURCE=2 -fstack-protector" \
 python -m pip install --upgrade -q pynacl --no-binary :all:

CC=/gccwrap CFLAGS_FILTER="-Wno-error=sign-conversion" \
 python -m pip install --upgrade -q cryptography --no-binary :all:

export PRCTL_SKIP_KERNEL_CHECK=yes

python -m pip install --upgrade \
       rpyc==3.4.4 pyaml rsa netaddr tinyec pyyaml ecdsa \
       paramiko pylzma pydbus python-ptrace psutil scandir \
       scapy colorama pyOpenSSL python-xlib msgpack-python \
       u-msgpack-python poster dnslib pyxattr pylibacl python-prctl \
       https://github.com/CoreSecurity/impacket/archive/master.zip \
       watchdog pulsectl pyalsaaudio pycryptodomex==3.7.0 --no-binary :all:

LDFLAGS="$LDFLAGS -lasound" python -m pip install --upgrade pyaudio

python -m pip -q install --upgrade --force-reinstall pycparser==2.17

echo "[+] Compile pykcp"
rm -rf $PYKCP/{kcp.so,kcp.pyd,kcp.dll,build,KCP.egg-info}
python -m pip install --upgrade --force $PYKCP
python -c 'import kcp' || exit 1

echo "[+] Compile opus"
( cd $PYOPUS && make clean && make && mv -f opus.so /usr/lib/python2.7/site-packages )
python -c 'import opus' || exit 1

echo "[+] Compile pyuv"

if [ "$TOOLCHAIN_ARCH" == "x86" ]; then
    CFLAGS_PYUV="-O2 -pipe -DCLOCK_MONOTONIC=1 -UHAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC"
    CFLAGS_PYUV="$CFLAGS_PYUV -U_FILE_OFFSET_BITS -D_XOPEN_SOURCE=600 "
    CFLAGS_PYUV="$CFLAGS_PYUV -D_GNU_SOURCE -DS_ISSOCK(m)='(((m) & S_IFMT) == S_IFSOCK)'"
    
    CC=/gccwrap CFLAGS_FILTER="-D_FILE_OFFSET_BITS=64" CFLAGS="$CFLAGS_PYUV" \
      python -m pip install pyuv --upgrade --no-binary :all:
else
    CFLAGS="$CFLAGS -D_XOPEN_SOURCE=600 -D_GNU_SOURCE -DS_ISSOCK(m)='(((m) & S_IFMT) == S_IFSOCK)'" \
	  python -m pip install pyuv --upgrade --no-binary :all:
fi

# python -m pip install --upgrade --no-binary :all: pycryptodome==3.7.0
python -m pip install --upgrade --no-binary :all: https://github.com/Legrandin/pycryptodome/archive/master.zip

cd /usr/lib/python2.7

echo "[+] Strip python modules"
find -name "*.so" | while read f; do strip $f; done

echo "[+] Build python template ($TOOLCHAIN_ARCH)"

rm -f ${TEMPLATES}/linux-${TOOLCHAIN_ARCH}.zip
zip -y -r -9 ${TEMPLATES}/linux-${TOOLCHAIN_ARCH}.zip . \
    -x "*.a" -x "*.la" -x "*.o" -x "*.whl" -x "*.txt" -x "*.pyo" -x "*.pyc" \
    -x "*test/*" -x "*tests/*" -x "*examples/*" \
    -x "*.egg-info/*" -x "*.dist-info/*" \
    -x "idlelib/*" -x "lib-tk/*" -x "tk*"  -x "tcl*" >/dev/null

ldconfig

echo "[+] Build pupy"

case $TOOLCHAIN_ARCH in
    amd64)
	MAKEFLAGS="ARCH=64"
	TARGETS="pupyx64d.lin pupyx64d.lin"
	TARGETS="$TARGETS pupyx64.lin pupyx64.lin.so"
	;;

    x86)
	MAKEFLAGS="ARCH=32 PIE="
	TARGETS="pupyx86d.lin pupyx86d.lin.so"
	TARGTS="$TARGETS pupyx86dpupyx86.lin pupyx86.lin.so"
	;;
esac

for target in $TARGETS; do rm -f $TEMPLATES/$target; done

cd $SRC

make distclean
make -j $MAKEFLAGS
make clean
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
