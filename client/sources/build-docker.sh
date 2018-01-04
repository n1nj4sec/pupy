#!/bin/sh

PACKAGES="rpyc rsa pefile rsa netaddr win_inet_pton netaddr tinyec pypiwin32"
PACKAGES_BUILD="pycryptodome cryptography netifaces"
PACKAGES="$PACKAGES pyaudio https://github.com/secdev/scapy/archive/master.zip pyOpenSSL colorama pyuv"
PACKAGES="$PACKAGES https://github.com/CoreSecurity/impacket/archive/master.zip"

SELF=`readlink -f "$0"`
SELFPWD=`dirname "$SELF"`
SRC=${SELFPWD:-`pwd`}

cd $SRC

WINPTY=../../pupy/external/winpty
PYKCP=../../pupy/external/pykcp

echo "[+] Install python packages"
for PYTHON in $PYTHON32 $PYTHON64; do
    $PYTHON -OO -m pip install -q --upgrade pip
    $PYTHON -OO -m pip install -q --upgrade setuptools
    $PYTHON -OO -m pip install -q pycparser==2.17
    $PYTHON -OO -m pip install $PACKAGES
    $PYTHON -OO -m pip install --no-binary :all: $PACKAGES_BUILD
    $PYTHON -OO -m pip install --upgrade --force $PYKCP
done

echo "[+] Install psutil"
$PYTHON32 -OO -m pip install --no-binary :all: psutil==4.3.1
$PYTHON64 -OO -m pip install --no-binary :all: psutil

echo "[+] Compile python files"
for PYTHON in $PYTHON32 $PYTHON64; do
    $PYTHON -m compileall -q C:\\Python27\\Lib >/dev/null || true
    $PYTHON -OO -m compileall -q C:\\Python27\\Lib >/dev/null || true
done

echo "[+] Compile pupymemexec /32"
$CL32 \
    ../../pupy/packages/src/pupymemexec/pupymemexec.c \
    /LD /D_WIN32 /IC:\\Python27\\Include \
    C:\\Python27\\libs\\python27.lib advapi32.lib \
    /FeC:\\Python27\\Lib\\site-packages\\pupymemexec.pyd

echo "[+] Compile pupymemexec /64"
$CL64 \
    ../../pupy/packages/src/pupymemexec/pupymemexec.c \
    /LD /D_WIN64 /IC:\\Python27\\Include \
    C:\\Python27\\libs\\python27.lib advapi32.lib \
    /FeC:\\Python27\\Lib\\site-packages\\pupymemexec.pyd

echo "[+] Compile winpty /32"
make -C ${WINPTY} clean
make -C ${WINPTY} MINGW_CXX="${MINGW32} -Os -s" build/winpty.dll
mv $WINPTY/build/winpty.dll ${WINE32}/drive_c/Python27/DLLs/

echo "[+] Compile winpty /64"
make -C ${WINPTY} clean
make -C ${WINPTY} MINGW_CXX="${MINGW64} -Os -s" build/winpty.dll
mv ${WINPTY}/build/winpty.dll ${WINE64}/drive_c/Python27/DLLs/

TEMPLATES=`readlink -f ../../pupy/payload_templates`

echo "[+] Build templates /32"
cd $WINE32/drive_c/Python27
rm -f ${TEMPLATES}/windows-x86.zip
for dir in Lib DLLs; do
cd $dir
zip -q -y \
    -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.py" -x "*.pyc" -x "*.chm" \
    -x "*test/*" -x "*tests/*" -x "*examples/*" -x "pythonwin/*" \
    -x "idlelib/*" -x "lib-tk/*" -x "tk*"  -x "tcl*" \
    -x "*.egg-info/*" -x "*.dist-info/*" -x "*.exe" \
    -r9 ${TEMPLATES}/windows-x86.zip .
cd -
done

cd $WINE64/drive_c/Python27
rm -f ${TEMPLATES}/windows-amd64.zip

echo "[+] Build templates /64"
for dir in Lib DLLs; do
cd $dir
zip -q -y \
    -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.py" -x "*.pyc" -x "*.chm" \
    -x "*test/*" -x "*tests/*" -x "*examples/*"	 -x "pythonwin/*" \
    -x "idlelib/*" -x "lib-tk/*" -x "tk*"  -x "tcl*" \
    -x "*.egg-info/*" -x "*.dist-info/*" -x "*.exe" \
    -r9 ${TEMPLATES}/windows-amd64.zip .
cd -
done

echo "[+] Build pupy"

TARGETS="pupyx64d.dll pupyx64d.exe pupyx64.dll pupyx64d.unc.dll pupyx64d.unc.exe"
TARGETS="$TARGETS pupyx64.exe pupyx64.unc.dll pupyx64.unc.exe pupyx86d.dll pupyx86d.exe pupyx86.dll"
TARGETS="$TARGETS pupyx86d.unc.dll pupyx86d.unc.exe pupyx86.exe pupyx86.unc.dll pupyx86.unc.exe"

cd ${SRC}

for target in $TARGETS; do rm -f $TEMPLATES/$target; done

make -f Makefile -j BUILDENV=/build ARCH=win32 clean
make -f Makefile -j BUILDENV=/build ARCH=win32
make -f Makefile -j BUILDENV=/build DEBUG=1 ARCH=win32 clean
make -f Makefile -j BUILDENV=/build DEBUG=1 ARCH=win32
make -f Makefile -j BUILDENV=/build ARCH=win32 UNCOMPRESSED=1 clean
make -f Makefile -j BUILDENV=/build ARCH=win32 UNCOMPRESSED=1 
make -f Makefile -j BUILDENV=/build DEBUG=1 ARCH=win32 UNCOMPRESSED=1 clean
make -f Makefile -j BUILDENV=/build DEBUG=1 ARCH=win32 UNCOMPRESSED=1 
make -f Makefile -j BUILDENV=/build ARCH=win64 distclean
make -f Makefile -j BUILDENV=/build ARCH=win64
make -f Makefile -j BUILDENV=/build DEBUG=1 ARCH=win64 clean
make -f Makefile -j BUILDENV=/build DEBUG=1 ARCH=win64
make -f Makefile -j BUILDENV=/build ARCH=win64 UNCOMPRESSED=1 clean
make -f Makefile -j BUILDENV=/build ARCH=win64 UNCOMPRESSED=1
make -f Makefile -j BUILDENV=/build DEBUG=1 ARCH=win64 UNCOMPRESSED=1 clean
make -f Makefile -j BUILDENV=/build DEBUG=1 ARCH=win64 UNCOMPRESSED=1
make -f Makefile -j BUILDENV=/build ARCH=win64 UNCOMPRESSED=1 distclean

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

