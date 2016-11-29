#!/bin/sh

unset WINEARCH WINEPREFIX

set -xe

SELF=`readlink -f $0`
CWD=`dirname $0`
SOURCES=`readlink -f $CWD/../../`

PYTHON64="https://www.python.org/ftp/python/2.7.12/python-2.7.12.amd64.msi"
PYTHON32="https://www.python.org/ftp/python/2.7.12/python-2.7.12.msi"
PYTHONVC="https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/VCForPython27.msi"
PYCRYPTO32="http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win32-py2.7.exe"
PYCRYPTO64="http://www.voidspace.org.uk/downloads/pycrypto26/pycrypto-2.6.win-amd64-py2.7.exe"

PACKAGES="rpyc psutil pyaml rsa pefile image rsa netaddr pypiwin32 win_inet_pton netaddr tinyec uptime"

BUILDENV=${1:-`pwd`/buildenv}

if [ -f $BUILDENV/.ready ]; then
    echo "Buildenv at $BUILDENV already prepared"
    exit 0
fi

WINE=${WINE:-wine}
WINE32="$BUILDENV/win32"
WINE64="$BUILDENV/win64"
DOWNLOADS="$BUILDENV/downloads"

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
    wget -cP $DOWNLOADS $dist
done

for prefix in $WINE32 $WINE64; do
    rm -f $prefix/dosdevices/y:
    rm -f $prefix/dosdevices/x:
    ln -s ../../downloads $prefix/dosdevices/y:
    ln -s $SOURCES $prefix/dosdevices/x:
done

WINEPREFIX=$WINE32 wineserver -k

[ ! -f $WINE32/drive_c/.python ] && \
    WINEPREFIX=$WINE32 msiexec /i Y:\\python-2.7.12.msi /q && \
    touch $WINE32/drive_c/.python

WINEPREFIX=$WINE32 wineboot -r
WINEPREFIX=$WINE32 wineserver -k

[ ! -f $WINE64/drive_c/.python ] && \
    WINEPREFIX=$WINE64 msiexec /i Y:\\python-2.7.12.amd64.msi /q && \
    touch $WINE64/drive_c/.python

WINEPREFIX=$WINE64 wineboot -r
WINEPREFIX=$WINE64 wineserver -k

for prefix in $WINE32 $WINE64; do
    [ ! -f $prefix/drive_c/.vc ] && \
	WINEPREFIX=$prefix msiexec /i Y:\\VCForPython27.msi /q && \
	touch $prefix/drive_c/.vc
done

for prefix in $WINE32 $WINE64; do
    WINEPREFIX=$prefix wine C:\\Python27\\python -O -m pip install --upgrade pip
    WINEPREFIX=$prefix wine C:\\Python27\\python -O -m pip install --upgrade $PACKAGES
done

WINEPREFIX=$WINE32 wine C:\\Python27\\python.exe -m easy_install -Z $PYCRYPTO32
WINEPREFIX=$WINE64 wine C:\\Python27\\python.exe -m easy_install -Z $PYCRYPTO64

cat >$WINE32/python.sh <<EOF
#!/bin/sh
unset WINEARCH
export WINEPREFIX=$WINE32
exec wine C:\\\\Python27\\\\python.exe "\$@"
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
exec wine "\$VCINSTALLDIR\\\\bin\\\\cl.exe" "\$@"
EOF
chmod +x $WINE32/cl.sh

cat >$WINE64/python.sh <<EOF
#!/bin/sh
unset WINEARCH
export WINEPREFIX=$WINE64
exec wine C:\\\\Python27\\\\python.exe "\$@"
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
exec wine "\$VCINSTALLDIR\\\\bin\\\\amd64\\\\cl.exe" "\$@"
EOF
chmod +x $WINE64/cl.sh

touch $BUILDENV/.ready
