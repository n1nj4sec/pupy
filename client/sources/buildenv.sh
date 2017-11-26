#!/bin/sh

sudo apt-get install wine mingw-w64

unset WINEARCH WINEPREFIX

set -xe

SELF=`readlink -f $0`
CWD=`dirname $0`
SOURCES=`readlink -f $CWD/../../`

PYTHON64="https://www.python.org/ftp/python/2.7.13/python-2.7.13.amd64.msi"
PYTHON32="https://www.python.org/ftp/python/2.7.13/python-2.7.13.msi"
PYTHONVC="https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/VCForPython27.msi"
WINETRICKS="https://raw.githubusercontent.com/Winetricks/winetricks/master/src/winetricks"

# PYCRYPTO32="http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win32-py2.7.exe"
# PYCRYPTO64="http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win-amd64-py2.7.exe"
# PYWIN32="http://downloads.sourceforge.net/project/pywin32/pywin32/Build%20220/pywin32-220.win32-py2.7.exe"
# PYWIN64="http://downloads.sourceforge.net/project/pywin32/pywin32/Build%20220/pywin32-220.win-amd64-py2.7.exe"

PACKAGES_BUILD="pycryptodome cryptography netifaces"

BUILDENV=${1:-`pwd`/buildenv}

WINE=${WINE:-wine}
WINE32="$BUILDENV/win32"
WINE64="$BUILDENV/win64"
DOWNLOADS="$BUILDENV/downloads"

create_templates() {
    TEMPLATES=`readlink -f ../../pupy/payload_templates`

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

    for dir in Lib DLLs; do
	cd $dir
	zip -q -y \
	    -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.py" -x "*.pyc" -x "*.chm" \
	    -x "*test/*" -x "*tests/*" -x "*examples/*"  -x "pythonwin/*" \
	    -x "idlelib/*" -x "lib-tk/*" -x "tk*"  -x "tcl*" \
	    -x "*.egg-info/*" -x "*.dist-info/*" -x "*.exe" \
	    -r9 ${TEMPLATES}/windows-amd64.zip .
	cd -
    done
}

if [ -f $BUILDENV/.ready ]; then
    echo "Buildenv at $BUILDENV already prepared"
    create_templates
    exit 0
fi


MINGW64=${MINGW64:-x86_64-w64-mingw32-g++}
MINGW32=${MINGW32:-i686-w64-mingw32-g++}

exec < /dev/null

WINPTY=../../pupy/external/winpty

mkdir -p "$BUILDENV"
mkdir -p "$DOWNLOADS"

WINEARCH=win32 WINEPREFIX=$WINE32 wineboot
if [ ! $? -eq 0 ]; then
    echo "apt-get install wine32"
    exit 1
fi

WINEARCH=win64 WINEPREFIX=$WINE64 wineboot
if [ ! $? -eq 0 ]; then
    echo "apt-get install wine64"
    exit 1
fi

for dist in $PYTHON32 $PYTHON64 $PYTHONVC $WINETRICKS; do
    wget -qcP $DOWNLOADS $dist
done

for prefix in $WINE32 $WINE64; do
    rm -f $prefix/dosdevices/y:
    rm -f $prefix/dosdevices/x:
    ln -s ../../downloads $prefix/dosdevices/y:
    ln -s $SOURCES $prefix/dosdevices/x:
done

WINEPREFIX=$WINE32 wineserver -k || true

[ ! -f $WINE32/drive_c/.python ] && \
    WINEPREFIX=$WINE32 msiexec /i Y:\\python-2.7.13.msi /q && \
    touch $WINE32/drive_c/.python

WINEPREFIX=$WINE32 wineboot -r
WINEPREFIX=$WINE32 wineserver -k  || true

[ ! -f $WINE64/drive_c/.python ] && \
    WINEPREFIX=$WINE64 msiexec /i Y:\\python-2.7.13.amd64.msi /q && \
    touch $WINE64/drive_c/.python

WINEPREFIX=$WINE64 wineboot -r
WINEPREFIX=$WINE64 wineserver -k || true

for prefix in $WINE32 $WINE64; do
    [ ! -f $prefix/drive_c/.vc ] && \
	WINEPREFIX=$prefix msiexec /i Y:\\VCForPython27.msi /q && \
	touch $prefix/drive_c/.vc
done

WINEPREFIX=$WINE32 sh $DOWNLOADS/winetricks winxp
WINEPREFIX=$WINE64 sh $DOWNLOADS/winetricks win7

WINEPREFIX=$WINE32 wine reg add 'HKCU\Software\Wine\DllOverrides' /t REG_SZ /v dbghelp /d '' /f

export WINEPREFIX=$WINE64

mkdir -p $WINE64/drive_c/windows/Microsoft.NET/Framework
mkdir -p $WINE64/drive_c/windows/Microsoft.NET/Framework64

touch $WINE64/drive_c/windows/Microsoft.NET/Framework/empty.txt
touch $WINE64/drive_c/windows/Microsoft.NET/Framework64/empty.txt

wine reg add 'HKCU\Software\Wine\DllOverrides' /t REG_SZ /v dbghelp /d '' /f

wine reg add \
     'HKCU\Software\Microsoft\DevDiv\VCForPython\9.0' \
     /t REG_SZ /v installdir \
     /d 'C:\Program Files (x86)\Common Files\Microsoft\Visual C++ for Python\9.0' \
     /f

wineboot -fr
wineserver -k || true

unset WINEPREFIX

for prefix in $WINE32 $WINE64; do
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q --upgrade pip
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q --upgrade setuptools
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q pycparser==2.17
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q rpyc
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q rsa
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q pefile
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q netaddr
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q win_inet_pton
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q tinyec
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q pypiwin32
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q pycryptodome
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q cryptography
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q netifaces
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q pyaudio
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q https://github.com/secdev/scapy/archive/master.zip
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q pyOpenSSL
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q colorama
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q pyuv
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q https://github.com/CoreSecurity/impacket/archive/master.zip
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q Pillow
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m pip install -q --no-binary :all: $PACKAGES_BUILD
done

WINEPREFIX=$WINE32 wine C:\\Python27\\python -OO -m pip install -q --no-binary :all: psutil==4.3.1
WINEPREFIX=$WINE64 wine C:\\Python27\\python -OO -m pip install -q --no-binary :all: psutil

for prefix in $WINE32 $WINE64; do
    WINEPREFIX=$prefix wine C:\\Python27\\python -m compileall -q C:\\Python27\\Lib || true
    WINEPREFIX=$prefix wine C:\\Python27\\python -OO -m compileall -q C:\\Python27\\Lib || true
done

# WINEPREFIX=$WINE32 wine C:\\Python27\\python.exe -m easy_install -Z $PYWIN32
# WINEPREFIX=$WINE64 wine C:\\Python27\\python.exe -m easy_install -Z $PYWIN64

cat >$WINE32/python.sh <<EOF
#!/bin/sh
unset WINEARCH
export WINEPREFIX=$WINE32
export LINK="/NXCOMPAT:NO /LTCG"
export CL="/O1 /GL /GS-"
exec wine C:\\\\Python27\\\\python.exe -OO "\$@"
EOF
chmod +x $WINE32/python.sh

cat >$WINE32/cl.sh <<EOF
#!/bin/sh
unset WINEARCH
export WINEPREFIX=$WINE32
export VCINSTALLDIR="C:\\\\Program Files\\\\Common Files\\\\Microsoft\\\\Visual C++ for Python\\\\9.0\\\\VC"
export WindowsSdkDir="C:\\\\Program Files\\\\Common Files\\\\Microsoft\\\\Visual C++ for Python\\\\9.0\\\\WinSDK"
export INCLUDE="\$VCINSTALLDIR\\\\Include;\$WindowsSdkDir\\\\Include"
export LIB="\$VCINSTALLDIR\\\\Lib;\$WindowsSdkDir\\\\Lib"
export LIBPATH="\$VCINSTALLDIR\\\\Lib;\$WindowsSdkDir\\\\Lib"
export LINK="/NXCOMPAT:NO /LTCG"
export CL="/GL /GS-"
exec wine "\$VCINSTALLDIR\\\\bin\\\\cl.exe" "\$@"
EOF
chmod +x $WINE32/cl.sh

cat >$WINE64/python.sh <<EOF
#!/bin/sh
unset WINEARCH
export WINEPREFIX=$WINE64
export LINK="/NXCOMPAT:NO /LTCG"
export CL="/O1 /GL /GS-"
exec wine C:\\\\Python27\\\\python.exe -OO "\$@"
EOF
chmod +x $WINE64/python.sh

cat >$WINE64/cl.sh <<EOF
#!/bin/sh
unset WINEARCH
export WINEPREFIX=$WINE64
export VCINSTALLDIR="C:\\\\Program Files (x86)\\\\Common Files\\\\Microsoft\\\\Visual C++ for Python\\\\9.0\\\\VC"
export WindowsSdkDir="C:\\\\Program Files (x86)\\\\Common Files\\\\Microsoft\\\\Visual C++ for Python\\\\9.0\\\\WinSDK"
export INCLUDE="\$VCINSTALLDIR\\\\Include;\$WindowsSdkDir\\\\Include"
export LIB="\$VCINSTALLDIR\\\\Lib\\\\amd64;\$WindowsSdkDir\\\\Lib\\\\x64"
export LIBPATH="\$VCINSTALLDIR\\\\Lib\\\\amd64;\$WindowsSdkDir\\\\Lib\\\\x64"
export LINK="/NXCOMPAT:NO /LTCG"
export CL="/GL /GS-"
exec wine "\$VCINSTALLDIR\\\\bin\\\\amd64\\\\cl.exe" "\$@"
EOF
chmod +x $WINE64/cl.sh

$WINE32/cl.sh \
    ../../pupy/packages/src/pupymemexec/pupymemexec.c \
    /LD /D_WIN32 /IC:\\Python27\\Include \
    C:\\Python27\\libs\\python27.lib advapi32.lib \
    /FeC:\\Python27\\Lib\\site-packages\\pupymemexec.pyd

$WINE64/cl.sh \
    ../../pupy/packages/src/pupymemexec/pupymemexec.c \
    /LD /D_WIN64 /IC:\\Python27\\Include \
    C:\\Python27\\libs\\python27.lib advapi32.lib \
    /FeC:\\Python27\\Lib\\site-packages\\pupymemexec.pyd

make -C ${WINPTY} clean
make -C ${WINPTY} MINGW_CXX="${MINGW32} -Os -s" build/winpty.dll
mv $WINPTY/build/winpty.dll ${BUILDENV}/win32/drive_c/Python27/DLLs/

make -C ${WINPTY} clean
make -C ${WINPTY} MINGW_CXX="${MINGW64} -Os -s" build/winpty.dll
mv ${WINPTY}/build/winpty.dll ${BUILDENV}/win64/drive_c/Python27/DLLs/

echo "[+] Creating bundles"

OPWD=`pwd`

create_templates

touch $BUILDENV/.ready
