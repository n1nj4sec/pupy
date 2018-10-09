#!/usr/bin/bash

set -e

exec 2>buildenv-sunos.log

BPWD=`pwd`
BUILDENV=$BPWD/buildenv-sunos
TEMPLATES=$BPWD/../../pupy/payload_templates

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
export CC=$BPWD/gccwrap

mkdir -p $BUILDENV

# VERSIONS /MAY/ BE UPDATED (In case of vulnerabilites)
OPENSSL_SRC="https://www.openssl.org/source/openssl-1.0.2p.tar.gz"
ZLIB_SRC="http://zlib.net/zlib-1.2.11.tar.gz"
SQLITE_SRC="http://www.sqlite.org/2018/sqlite-autoconf-3220000.tar.gz"
LIBFFI_SRC="http://http.debian.net/debian/pool/main/libf/libffi/libffi_3.2.1.orig.tar.gz"
PYTHON_SRC="https://www.python.org/ftp/python/2.7.15/Python-2.7.15.tgz"

export PATH="$BUILDENV/build/bin:/opt/csw/bin/:/usr/sfw/bin/:/usr/ccs/bin/:/usr/xpg4/bin/:$PATH"

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
export LDFLAGS_NODEFS="-Wl,-i -m64 -fPIC -L$BUILDENV/build/lib -static-libgcc -lc -Wl,-znow -Wl,-zignore"
export LDFLAGS_DEFS="-Wl,-i -m64 -fPIC -L$BUILDENV/build/lib -static-libgcc -lc -Wl,-zdefs -Wl,-znow -Wl,-zignore"
export LDFLAGS=$LDFLAGS_DEFS
export PKG_CONFIG_PATH="$BUILDENV/build/lib/pkgconfig"
set -x

ln -sf /usr/lib/amd64/libcrypt_i.so /usr/lib/amd64/libcrypt.so

cd $BUILDENV/src/zlib-1.2.11
./configure --64 --static --prefix=$BUILDENV/build; gmake; gmake install

cd $BUILDENV/src/libffi-3.2.1
./configure --enable-static --disable-shared --prefix=$BUILDENV/build; make; make install

cd $BUILDENV/src/sqlite-autoconf-3220000
./configure --enable-static --disable-shared --prefix=$BUILDENV/build; gmake; gmake install

cd $BUILDENV/src/openssl-1.0.2p
./Configure --openssldir=$BUILDENV/build/ shared solaris64-x86_64-gcc; gmake; gmake install

export GCCWRAP_CFLAGS_EXTRA=-std=gnu99
export LDFLAGS=$LDFLAGS_NODEFS

cd $BUILDENV/src/Python-2.7.15
[ -f $BPWD/Python.SunOS10.Setup.dist ] && \
	cp -f $BPWD/Python.SunOS10.Setup.dist $BUILDENV/src/Python-2.7.15/Modules/Setup.dist

./configure --with-ensurepip=install --enable-unicode=ucs4 \
	    --with-system-ffi --enable-ipv6 --prefix=$BUILDENV/build \
	    CFLAGS="$CFLAGS -DXML_DEV_URANDOM"
gmake; gmake install
gcc -m64 --without-libgcc -shared -fPIC -o $BUILDENV/build/lib/libpython2.7.so \
    -Wl,--whole-archive libpython2.7.a -Wl,--no-whole-archive \
    -lc -lnsl -lsocket -lz -lm -ldl -lrt \
    $BUILDENV/build/lib/libssl.so $BUILDENV/build/lib/libcrypto.so \
    -lpthread \
    -Wl,--no-undefined -Wl,-zignore -Wl,-zdefs -Wl,-znow -Wl,-h,libpython2.7.so.1.0

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

cat >$BUILDENV/build/certs/b155520b.0 << __EOF__
-----BEGIN CERTIFICATE-----
MIIEizCCA3OgAwIBAgIORvCM288sVGbvMwHdXzQwDQYJKoZIhvcNAQELBQAwVzEL
MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsT
B1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xNTA4MTkw
MDAwMDBaFw0yNTA4MTkwMDAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBH
bG9iYWxTaWduIG52LXNhMS0wKwYDVQQDEyRHbG9iYWxTaWduIENsb3VkU1NMIENB
IC0gU0hBMjU2IC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCj
wHXhMpjl2a6EfI3oI19GlVtMoiVw15AEhYDJtfSKZU2Sy6XEQqC2eSUx7fGFIM0T
UT1nrJdNaJszhlyzey2q33egYdH1PPua/NPVlMrJHoAbkJDIrI32YBecMbjFYaLi
blclCG8kmZnPlL/Hi2uwH8oU+hibbBB8mSvaSmPlsk7C/T4QC0j0dwsv8JZLOu69
Nd6FjdoTDs4BxHHT03fFCKZgOSWnJ2lcg9FvdnjuxURbRb0pO+LGCQ+ivivc41za
Wm+O58kHa36hwFOVgongeFxyqGy+Z2ur5zPZh/L4XCf09io7h+/awkfav6zrJ2R7
TFPrNOEvmyBNVBJrfSi9AgMBAAGjggFTMIIBTzAOBgNVHQ8BAf8EBAMCAQYwHQYD
VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAw
HQYDVR0OBBYEFKkrh+HOJEc7G7/PhTcCVZ0NlFjmMB8GA1UdIwQYMBaAFGB7ZhpF
DZfKiVAvfQTNNKj//P1LMD0GCCsGAQUFBwEBBDEwLzAtBggrBgEFBQcwAYYhaHR0
cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vcm9vdHIxMDMGA1UdHwQsMCowKKAmoCSG
Imh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC5jcmwwVgYDVR0gBE8wTTAL
BgkrBgEEAaAyARQwPgYGZ4EMAQICMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3
Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQCi
HWmKCo7EFIMqKhJNOSeQTvCNrNKWYkc2XpLR+sWTtTcHZSnS9FNQa8n0/jT13bgd
+vzcFKxWlCecQqoETbftWNmZ0knmIC/Tp3e4Koka76fPhi3WU+kLk5xOq9lF7qSE
hf805A7Au6XOX5WJhXCqwV3szyvT2YPfA8qBpwIyt3dhECVO2XTz2XmCtSZwtFK8
jzPXiq4Z0PySrS+6PKBIWEde/SBWlSDBch2rZpmk1Xg3SBufskw3Z3r9QtLTVp7T
HY7EDGiWtkdREPd76xUJZPX58GMWLT3fI0I6k2PMq69PVwbH/hRVYs4nERnh9ELt
IjBrNRpKBYCkZd/My2/Q
-----END CERTIFICATE-----
__EOF__

cat >$BUILDENV/build/certs/5ad8a5d6.0 << __EOF__
-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz
yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE
38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP
AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad
DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----
__EOF__

python -m pip install --upgrade six packaging appdirs setuptools

export CFLAGS_FILTER="-Wno-error=sign-conversion"

python -m pip install \
       rpyc==3.4.4 pyaml rsa netaddr tinyec pyyaml ecdsa \
       paramiko uptime cryptography cffi pylzma pydbus python-ptrace scandir \
       scapy colorama pyOpenSSL python-xlib msgpack-python \
       u-msgpack-python poster dnslib \
       --upgrade --no-binary :all:

python -m pip install --upgrade pycryptodome

python -m pip install --force-reinstall pycparser==2.17 
python -m pip install git+https://github.com/alxchk/psutil.git@fix_sunos10_1346

export LDFLAGS="$LDFLAGS -lsendfile -lkstat"
export CFLAGS="$CFLAGS -Dstrnlen\\(x,l\\)=strlen\\(x\\)"
python -m pip install git+https://github.com/alxchk/pyuv.git@solaris10
python -m pip install git+https://github.com/alxchk/pykcp.git

cd $BUILDENV/build/lib/python2.7

find . -name "*.so*" | while read lib; do strip $lib; done

zip -y \
    -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.pyc" -x "*.pyo" \
    -x "*test/*" -x "*tests/*" -x "*examples/*" \
    -r9 ${TEMPLATES}/solaris-`uname -m`.zip .


