#!/usr/bin/bash

set -e

exec 2>buildenv-sunos.log

BUILDENV=`pwd`/buildenv-sunos
TEMPLATES=`pwd`/../../pupy/payload_templates

cat >gccwrap << '__EOF__'
#!/usr/bin/bash
declare -a filter=( "$CFLAGS_FILTER" )
declare -a badargs=( "$CFLAGS_ABORT" )
declare -a outargs=()

for arg; do
  found=false
  for filtered in ${filter[@]}; do
     if [ "$filtered" == "$arg" ]; then
        found=true
        break
     fi
  done

  for bad in ${badargs[@]}; do
     if [ "$bad" == "$arg" ]; then
        echo "Unsupported argument found: $bad"
        exit 1
     fi
  done

  if [ "$found" = "false" ]; then
        outargs[${#outargs[@]}]="$arg"
  fi

done

exec gcc $GCCWRAP_CFLAGS_EXTRA "${outargs[@]}"
__EOF__

chmod +x gccwrap
export CC=`pwd`/gccwrap

mkdir -p $BUILDENV

# VERSIONS /MAY/ BE UPDATED (In case of vulnerabilites)
OPENSSL_SRC="https://www.openssl.org/source/openssl-1.0.2n.tar.gz"
ZLIB_SRC="http://zlib.net/zlib-1.2.11.tar.gz"
SQLITE_SRC="http://www.sqlite.org/2018/sqlite-autoconf-3220000.tar.gz"
LIBFFI_SRC="http://http.debian.net/debian/pool/main/libf/libffi/libffi_3.2.1.orig.tar.gz"
PYTHON_SRC="https://www.python.org/ftp/python/2.7.14/Python-2.7.14.tgz"

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

cd $BUILDENV/src/sqlite-autoconf-3220000
./configure --enable-static --disable-shared --prefix=$BUILDENV/build; gmake; gmake install

cd $BUILDENV/src/openssl-1.0.2n
./Configure --openssldir=$BUILDENV/build/ shared solaris64-x86_64-gcc; gmake; gmake install

export GCCWRAP_CFLAGS_EXTRA=-std=gnu99
cd $BUILDENV/src/Python-2.7.14
./configure --with-ensurepip=install --enable-unicode=ucs4 --with-system-ffi --enable-ipv6 --enable-shared --prefix=$BUILDENV/build
gmake; gmake install

unset GCCWRAP_CFLAGS_EXTRA

cat >$BUILDENV/build/certs/244b5494.0 << __EOF__
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug
RVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm
+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTW
PNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEM
xChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFB
Ik5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3
hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsg
EsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaA
FLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3Nec
nzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6z
eM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jF
hS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2
Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCe
vEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep
+OkuE6N36B9K
-----END CERTIFICATE-----
__EOF__

python -m pip install --upgrade six packaging appdirs setuptools

export CFLAGS_FILTER="-Wno-error=sign-conversion"

python -m pip install \
       rpyc pycryptodome pyaml rsa netaddr tinyec pyyaml ecdsa \
       paramiko uptime cryptography cffi pylzma pydbus python-ptrace scandir \
       scapy colorama pyOpenSSL python-xlib msgpack-python \
       u-msgpack-python poster \
       --upgrade --no-binary :all:

python -m pip install --force-reinstall pycparser==2.17 

python -m pip install --force-reinstall git+https://github.com/alxchk/psutil.git

export LDFLAGS="$LDFLAGS -lsendfile -lkstat"
python -m pip install git+https://github.com/alxchk/pyuv.git
python -m pip install git+https://github.com/alxchk/pykcp.git

cd $BUILDENV/build/lib/python2.7

zip -y \
    -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.pyc" -x "*.pyo" \
    -x "*test/*" -x "*tests/*" -x "*examples/*" \
    -r9 ${TEMPLATES}/solaris-`uname -m`.zip .


