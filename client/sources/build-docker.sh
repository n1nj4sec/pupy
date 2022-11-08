#!/bin/sh

PACKAGES_BUILD="netifaces msgpack-python u-msgpack-python construct bcrypt watchdog dukpy impacket zeroconf ushlex"
PACKAGES_BUILD="$PACKAGES_BUILD pycryptodomex pycryptodome cryptography pyOpenSSL paramiko"

PACKAGES="rsa pefile win_inet_pton netaddr pywin32 win_inet_pton dnslib"
PACKAGES="$PACKAGES pyaudio https://github.com/secdev/scapy/archive/master.zip colorama pyaudio"
PACKAGES="$PACKAGES https://github.com/alxchk/pypykatz/archive/master.zip"
PACKAGES="$PACKAGES https://github.com/warner/python-ed25519/archive/master.zip"
PACKAGES="$PACKAGES https://github.com/alxchk/tinyec/archive/master.zip"
PACKAGES="$PACKAGES https://github.com/alxchk/urllib-auth/archive/master.zip"
PACKAGES="$PACKAGES https://github.com/alxchk/winkerberos/archive/master.zip"
PACKAGES="$PACKAGES https://github.com/alxchk/pyuv/archive/v1.x.zip"
PACKAGES="$PACKAGES idna http-parser pyodbc wmi"

SUFFIX="-310"
SELF=$(readlink -f "$0")
SELFPWD=$(dirname "$SELF")
SRC=${SELFPWD:-$(pwd)}
PUPY=$(readlink -f ../../pupy)

cd $SRC

EXTERNAL=$(readlink -f ../../pupy/external)
TEMPLATES=$(readlink -f ../../pupy/payload_templates)
WINPTY=$EXTERNAL/winpty
PYKCP=$EXTERNAL/pykcp
PYOPUS=$EXTERNAL/pyopus/src

$PYTHON32 -m pip install -q --upgrade pylzma
$PYTHON64 -m pip install -q --upgrade pylzma


SKIP_TO_BUILD=0
if [ ! "$SKIP_TO_BUILD" -eq "1" ]; then

echo "[+] Install python packages"
for PYTHON in $PYTHON32 $PYTHON64; do
    $PYTHON -m pip install -q --upgrade pip
    $PYTHON -m pip install -q --upgrade setuptools cython

    # Still problems here
    $PYTHON -m pip install -q --upgrade pynacl

    $PYTHON -m pip install --upgrade pycryptodome
    $PYTHON -m pip install --upgrade $PACKAGES_BUILD

    NO_JAVA=1 \
        $PYTHON -m pip install --upgrade --force-reinstall \
        https://github.com/alxchk/pyjnius/archive/master.zip

    $PYTHON -m pip install --upgrade --force-reinstall \
        https://github.com/alxchk/scandir/archive/master.zip

    $PYTHON -m pip install --upgrade $PACKAGES

    $PYTHON -c "from Crypto.Cipher import AES; AES.new"
    if [ ! $? -eq 0 ]; then
        echo "pycryptodome build failed"
        exit 1
    fi

    rm -rf $PYKCP/{kcp.so,kcp.pyd,kcp.dll,build,KCP.egg-info}
    $PYTHON -m pip install --upgrade --force $PYKCP
    $PYTHON -c 'import kcp' || exit 1
done

echo "[+] Install psutil"
$PYTHON32 -m pip install psutil
$PYTHON64 -m pip install --upgrade psutil

for PYTHON in $PYTHON32 $PYTHON64; do
    $PYTHON -m pip install -q --force pycparser
done

#cd $PYOPUS
#echo "[+] Compile opus /32"
#git clean -fdx
#make -f Makefile.msvc CL=$CL32
#mv opus.pyd ${PYTHONPATH32}/Lib/site-packages/

#echo "[+] Compile opus /64"
#git clean -fdx
#make -f Makefile.msvc CL=$CL64
#mv -f opus.pyd ${PYTHONPATH64}/Lib/site-packages/

echo "[+] Compile winpty /32"
rm -f $WINPTY/build/winpty.dll
make -C ${WINPTY} clean
make -C ${WINPTY} MINGW_CXX="${MINGW32}-win32 -mabi=ms -Os" V=1 build/winpty.dll
if [ ! -f $WINPTY/build/winpty.dll ]; then
    echo "WinPTY/x86 build failed"
    exit 1
fi

mv $WINPTY/build/winpty.dll ${PYTHONPATH32}/DLLs/

echo "[+] Compile winpty /64"
rm -f $WINPTY/build/winpty.dll
make -C ${WINPTY} clean
make -C ${WINPTY} MINGW_CXX="${MINGW64}-win32 -mabi=ms -Os" V=1 build/winpty.dll
if [ ! -f $WINPTY/build/winpty.dll ]; then
    echo "WinPTY/x64 build failed"
    exit 1
fi

mv ${WINPTY}/build/winpty.dll ${PYTHONPATH64}/DLLs/

echo "[+] Build templates /32"
cd ${PYTHONPATH32}
rm -f ${TEMPLATES}/windows-x86${SUFFIX}.zip
for dir in Lib DLLs; do
    cd $dir
    zip -q -y \
        -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.pyo" -x "*.pyc" -x "*.chm" \
        -x "*test/*" -x "*tests/*" -x "*examples/*" -x "pythonwin/*" \
        -x "idlelib/*" -x "lib-tk/*" -x "tk*" -x "tcl*" \
        -x "*.egg-info/*" -x "*.dist-info/*" -x "*.exe" \
        -r9 ${TEMPLATES}/windows-x86${SUFFIX}.zip .
    cd -
done
cd ${PYTHONPATH64}
rm -f ${TEMPLATES}/windows-amd64${SUFFIX}.zip

echo "[+] Build templates /64"
for dir in Lib DLLs; do
    cd $dir
    zip -q -y \
        -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.pyo" -x "*.pyc" -x "*.chm" \
        -x "*test/*" -x "*tests/*" -x "*examples/*" -x "pythonwin/*" \
        -x "idlelib/*" -x "lib-tk/*" -x "tk*" -x "tcl*" \
        -x "*.egg-info/*" -x "*.dist-info/*" -x "*.exe" \
        -r9 ${TEMPLATES}/windows-amd64${SUFFIX}.zip .
    cd -
done

fi

echo "[+] Build pupy"

TARGETS="pupyx64d.dll pupyx64d.exe pupyx64.dll pupyx64.exe"
TARGETS="$TARGETS pupyx86d.dll pupyx86d.exe pupyx86.dll pupyx86.exe"
TARGETS="$TARGETS "

cd ${SRC}

for target in $TARGETS; do rm -f $TEMPLATES/$target; done

set -e

#make -f Makefile -j BUILDENV=/opt DEBUG=1 FEATURE_DYNLOAD=1 FEATURE_POSTMORTEM=1 ARCH=32

make -f Makefile -j BUILDENV=/opt DEBUG=1 FEATURE_DYNLOAD=1 ARCH=32 clean
make -f Makefile -j BUILDENV=/opt DEBUG=1 FEATURE_DYNLOAD=1 ARCH=32
make -f Makefile -j BUILDENV=/opt DEBUG=1 FEATURE_DYNLOAD=1 ARCH=32 clean

make -f Makefile -j BUILDENV=/opt FEATURE_DYNLOAD=1 ARCH=32 clean
make -f Makefile -j BUILDENV=/opt FEATURE_DYNLOAD=1 ARCH=32
make -f Makefile -j BUILDENV=/opt FEATURE_DYNLOAD=1 ARCH=32 clean

make -f Makefile -j BUILDENV=/opt DEBUG=1 FEATURE_DYNLOAD=1 ARCH=64 clean
make -f Makefile -j BUILDENV=/opt DEBUG=1 FEATURE_DYNLOAD=1 ARCH=64
make -f Makefile -j BUILDENV=/opt DEBUG=1 FEATURE_DYNLOAD=1 ARCH=64 clean

make -f Makefile -j BUILDENV=/opt FEATURE_DYNLOAD=1 ARCH=64 clean
make -f Makefile -j BUILDENV=/opt FEATURE_DYNLOAD=1 ARCH=64
make -f Makefile -j BUILDENV=/opt FEATURE_DYNLOAD=1 ARCH=64 clean




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
