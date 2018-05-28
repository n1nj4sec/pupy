#!/bin/sh

##########################################################################################
#                               PRINT WITH COLORS
##########################################################################################
COLOR_ECHO_ENABLED=true
COLOR_GREEN="\033[0;32m"
COLOR_GREEN_B="\033[1;32m"
COLOR_END="\033[0m"
echoGreen() {
    if $COLOR_ECHO_ENABLED ; then
        echo "${COLOR_GREEN}${1}${COLOR_END}"
    else
        echo "${1}"
    fi
}
echoGreenB() {
    if $COLOR_ECHO_ENABLED ; then
        echo "${COLOR_GREEN_B}${1}${COLOR_END}"
    else
        echo "${1}"
    fi
}
##########################################################################################

BUILD_ENV=true

while getopts "cbh" option
do
    case $option in
    b)
        echo "[+] Don't build environments (buildenv.sh script)"
        BUILD_ENV=false
        ;;
    c)
        echo "[+] Disable color output"
        COLOR_ECHO_ENABLED=false
        ;;
    h)
        echo "[+] Help menu"
        echo " -b: Don't build environments (buildenv.sh script)"
        echo " -c: Disable color output"
        exit 0
        ;;
    esac
done


if $BUILD_ENV ; then
    echoGreenB "[+] Building environments before creating Windows binaries"
    ./buildenv.sh
else
    echoGreenB "[+] Environments are not created before creating Windows binaries."
    echoGreenB "[+] buildenv.sh is not started"
fi


echoGreenB "[+] Cleaning default win32 binary..."
make -f Makefile -j ARCH=win32 clean
echoGreenB "[+] Generating default win32 binary..."
make -f Makefile -j ARCH=win32
echoGreenB "[+] Cleaning debug win32 binary..."
make -f Makefile -j DEBUG=1 ARCH=win32 clean
echoGreenB "[+] Generating debug win32 binary..."
make -f Makefile -j DEBUG=1 ARCH=win32
echoGreenB "[+] Cleaning uncompressed win32 binary..."
make -f Makefile -j ARCH=win32 UNCOMPRESSED=1 clean
echoGreenB "[+] Generating uncompressed win32 binary..."
make -f Makefile -j ARCH=win32 UNCOMPRESSED=1
echoGreenB "[+] Cleaning debug uncompressed win32 binary..."
make -f Makefile -j DEBUG=1 ARCH=win32 UNCOMPRESSED=1 clean
echoGreenB "[+] Generating debug uncompressed win32 binary..."
make -f Makefile -j DEBUG=1 ARCH=win32 UNCOMPRESSED=1 
echoGreenB "[+] Cleaning dist default win64 binary..."
make -f Makefile -j ARCH=win64 distclean
echoGreenB "[+] Generating default win64 binary..."
make -f Makefile -j ARCH=win64
echoGreenB "[+] Cleaning debug win64 binary..."
make -f Makefile -j DEBUG=1 ARCH=win64 clean
echoGreenB "[+] Generating debug win64 binary..."
make -f Makefile -j DEBUG=1 ARCH=win64
echoGreenB "[+] Cleaning uncompressed win64 binary..."
make -f Makefile -j ARCH=win64 UNCOMPRESSED=1 clean
echoGreenB "[+] Generating uncompressed win64 binary..."
make -f Makefile -j ARCH=win64 UNCOMPRESSED=1
echoGreenB "[+] Cleaning debug uncompressed win64 binary..."
make -f Makefile -j DEBUG=1 ARCH=win64 UNCOMPRESSED=1 clean
echoGreenB "[+] Generating debug uncompressed win64 binary..."
make -f Makefile -j DEBUG=1 ARCH=win64 UNCOMPRESSED=1
echoGreenB "[+] Cleaning dist debug uncompressed win64 binary..."
make -f Makefile -j ARCH=win64 UNCOMPRESSED=1 distclean
