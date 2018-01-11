#!/bin/sh

SELF=`readlink -f "$0"`
SELFPWD=`dirname "$SELF"`
SRC=${SELFPWD:-`pwd`}

cd $SRC

TEMPLATES=`readlink -f ../../pupy/payload_templates`

PYKCP=../../pupy/external/pykcp

set -e

echo "[+] Install python packages"

python -OO -m pip install --upgrade setuptools
python -OO -m pip install pycparser==2.17
python -OO -m pip install -q six packaging appdirs

CC=/gccwrap CFLAGS_ABORT="-D_FORTIFY_SOURCE=2 -fstack-protector" \
 python -OO -m pip install -q pynacl --no-binary :all:

CC=/gccwrap CFLAGS_FILTER="-Wno-error=sign-conversion" \
 python -OO -m pip install -q cryptography --no-binary :all:

python -OO -m pip install \
       rpyc pycryptodome pyaml rsa netaddr tinyec pyyaml ecdsa \
       paramiko pylzma pydbus python-ptrace psutil scandir \
       scapy impacket colorama pyOpenSSL python-xlib msgpack-python \
       u-msgpack-python poster \
       --no-binary :all:

echo "[+] Compile pykcp"
python -OO -m pip install $PYKCP

echo "[+] Compile pyuv"

if [ "$TOOLCHAIN_ARCH" == "x86" ]; then
    CFLAGS_PYUV="-O2 -pipe -DCLOCK_MONOTONIC=1 -UHAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC"
    CFLAGS_PYUV="$CFLAGS_PYUV -U_FILE_OFFSET_BITS -D_XOPEN_SOURCE=600 "
    CFLAGS_PYUV="$CFLAGS_PYUV -D_GNU_SOURCE -DS_ISSOCK(m)='(((m) & S_IFMT) == S_IFSOCK)'"
    
    CC=/gccwrap CFLAGS_FILTER="-D_FILE_OFFSET_BITS=64" CFLAGS="$CFLAGS_PYUV" \
      python -OO -m pip install pyuv --no-binary :all:
else
    CFLAGS="$CFLAGS -D_XOPEN_SOURCE=600 -D_GNU_SOURCE -DS_ISSOCK(m)='(((m) & S_IFMT) == S_IFSOCK)'" \
	  python -OO -m pip install pyuv --no-binary :all:
fi

echo "[+] Compile python files"
cd /usr/lib/python2.7
find -name "*.py" | python -m compileall -qfi -
find -name "*.py" | python -OO -m compileall -qfi -

echo "[+] Strip python modules"
find -name "*.so" | while read f; do strip $f; done

echo "[+] Build python template ($TOOLCHAIN_ARCH)"

rm -f ${TEMPLATES}/linux-${TOOLCHAIN_ARCH}.zip
zip -y -r -9 ${TEMPLATES}/linux-${TOOLCHAIN_ARCH}.zip . \
    -x "*.a" -x "*.la" -x "*.o" -x "*.whl" -x "*.txt" -x "*.py" -x "*.pyc" \
    -x "*test/*" -x "*tests/*" -x "*examples/*" \
    -x "*.egg-info/*" -x "*.dist-info/*" \
    -x "idlelib/*" -x "lib-tk/*" -x "tk*"  -x "tcl*" >/dev/null

ldconfig

echo "[+] Build pupy"

case $TOOLCHAIN_ARCH in
    amd64)
	MAKEFLAGS="ARCH=64 PIE="
	TARGETS="pupyx64d.lin pupyx64d.lin.so pupyx64d.unc.lin"
	TARGETS="$TARGETS pupyx64d.unc.lin.so pupyx64.lin pupyx64.lin.so"
	TARGETS="$TARGETS pupyx64.unc.lin pupyx64.unc.lin.so"
	;;

    x86)
	MAKEFLAGS="ARCH=32 PIE="
	TARGETS="pupyx86d.lin pupyx86d.lin.so"
	TARGTS="$TARGETS pupyx86d.unc.lin pupyx86d.unc.lin.so pupyx86.lin pupyx86.lin.so"
	TARGETS="$TARGETS pupyx86.unc.lin pupyx86.unc.lin.so"
	;;
esac

for target in $TARGETS; do rm -f $TEMPLATES/$target; done

cd $SRC

make clean
make -j $MAKEFLAGS
make clean
make -j DEBUG=1 $MAKEFLAGS
make clean
make -j UNCOMPRESSED=1 $MAKEFLAGS
make clean
make -j DEBUG=1 UNCOMPRESSED=1 $MAKEFLAGS
make distclean

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

