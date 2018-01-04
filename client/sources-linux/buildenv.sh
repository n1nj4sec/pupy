#!/bin/sh

export PATH=/sbin:/usr/sbin:/usr/local/sbin:/bin:/usr/bin:/usr/local/sbin:$HOME/.local/bin
export XID=`id -u`

# VERSIONS /MAY/ BE UPDATED (In case of vulnerabilites)
OPENSSL_SRC="http://cdn-fastly.deb.debian.org/debian/pool/main/o/openssl/openssl_1.0.2l.orig.tar.gz"
ZLIB_SRC="http://zlib.net/zlib-1.2.11.tar.gz"
SQLITE_SRC="http://www.sqlite.org/2016/sqlite-autoconf-3150200.tar.gz"
LIBFFI_SRC="http://http.debian.net/debian/pool/main/libf/libffi/libffi_3.2.1.orig.tar.gz"
PYTHON_SRC="https://www.python.org/ftp/python/2.7.13/Python-2.7.13.tgz"
PKGCONFIG_SRC="https://pkg-config.freedesktop.org/releases/pkg-config-0.29.1.tar.gz"
XZ_SRC="http://tukaani.org/xz/xz-5.2.2.tar.gz"
M4_SRC="https://ftp.gnu.org/gnu/m4/m4-1.4.18.tar.gz"
AUTOCONF_SRC="https://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz"
AUTOMAKE_SRC="https://ftp.gnu.org/gnu/automake/automake-1.15.tar.gz"

# VERSIONS ARE IMPORTANT
MAKE_SRC="http://ftp.gnu.org/gnu/make/make-3.82.tar.gz"
GLIB_SRC="https://ftp.gnome.org/pub/gnome/sources/glib/2.32/glib-2.32.4.tar.xz"
DBUS_SRC="https://dbus.freedesktop.org/releases/dbus/dbus-1.2.12.tar.gz"
DBUS_GLIB_SRC="https://dbus.freedesktop.org/releases/dbus-glib/dbus-glib-0.88.tar.gz"
GOBJECT_INTROSPECTION="http://ftp.gnome.org/pub/gnome/sources/gobject-introspection/1.32/gobject-introspection-1.32.1.tar.xz"
PYGOBJECT="http://ftp.gnome.org/pub/GNOME/sources/pygobject/3.2/pygobject-3.2.2.tar.xz"
DBUS_PYTHON="https://dbus.freedesktop.org/releases/dbus-python/dbus-python-0.84.0.tar.gz"

if [ ! -d buildenv/downloads ]; then
    mkdir -p buildenv/downloads
    cd buildenv/downloads
    for bin in "$MAKE_SRC" "$OPENSSL_SRC" "$ZLIB_SRC" "$SQLITE_SRC" "$LIBFFI_SRC" \
                           "$PYTHON_SRC" "$PKGCONFIG_SRC" "$GLIB_SRC" "$XZ_SRC"  \
                           "$DBUS_SRC" "$DBUS_GLIB_SRC" "$GOBJECT_INTROSPECTION" \
                           "$PYGOBJECT" "$DBUS_PYTHON" "$M4_SRC" "$AUTOCONF_SRC" \
			   "$AUTOMAKE_SRC" ; do
        wget -c "$bin"
    done
    cd -
    
fi

if [ ! $XID -eq 0 ]; then
    echo "[!] You need to become root to run rest of this script (uid=$XID)"
    su -c "./$0 $XID"
    exit
fi

XID="$1"

echo "USER XID: $XID"

if [ ! -f buildenv/lin32/.ready ]; then

debootstrap --arch i386 woody buildenv/lin32 http://archive.debian.org/debian >/dev/null
mkdir -p buildenv/lin32/usr/src
cp -vfp buildenv/downloads/* buildenv/lin32/usr/src/

mkdir -p buildenv/lin32/etc/ssl/certs
for file in /etc/ssl/certs/*.0; do
    cat $file >buildenv/lin32/etc/ssl/certs/`basename "$file"`
done
cp /etc/ssl/certs/ca-* buildenv/lin32/etc/ssl/certs/

cat /etc/resolv.conf >buildenv/lin32/etc/resolv.conf

cat > buildenv/lin32/wrap.c <<EOF
#define _GNU_SOURCE
#include <sys/utsname.h>
#include <string.h>

static const
struct utsname pupy_utsname = {
  .sysname = "Linux",
  .nodename = "Pupy",
  .release = "2.4.0",
  .version = "2.4.0",
  .machine = "i386",
  .domainname = "Pupy",
} ;

int uname(struct utsname *buf) {
    memcpy(buf, &pupy_utsname, sizeof(struct utsname));
    return 0;
}
EOF

cat > buildenv/lin32/gccwrap <<EOF
#!/bin/bash
declare -a filter=( "\$CFLAGS_FILTER" )
declare -a outargs=()

for arg; do
  found=false
  for filtered in \${filter[@]}; do
     if [ "\$filtered" == "\$arg" ]; then
        found=true
        break
     fi
  done

  if [ "\$found" = "false" ]; then
        outargs[\${#outargs[@]}]="\$arg"
  fi

done

exec gcc "\${outargs[@]}"
EOF

chmod +x buildenv/lin32/gccwrap

cat <<__CMDS__ > buildenv/lin32/deploy.sh

exec 1>/log.txt
set -x

export MAKEOPTS="-j 2"
export LC_ALL=C

useradd -u $XID -m pupy

export TERM=
export DEBIAN_FRONTEND=noninteractive
/bin/sh -c "apt-get --force-yes -y install gcc-3.0 make libc-dev \
 perl m4 gettext libexpat1-dev flex bison file libstdc++2.10-dev \
 libtool patch xutils xlibs-dev < /dev/null"

cd /
gcc -fPIC -o /wrap.so -shared /wrap.c
echo /wrap.so >/etc/ld.so.preload

mkdir /opt/static
ln -sf /usr/lib/gcc-lib/i386-linux/3.0.4/libgcc.a /opt/static/
ln -sf /usr/lib/libffi.a /opt/static/
ln -sf /usr/lib/libutil.a /opt/static/
ln -sf /usr/bin/gcc-3.0 /usr/bin/gcc
ln -sf /usr/bin/gcc-3.0 /usr/bin/cc
ln -sf /usr/X11R6/lib/libX11.so /usr/lib/
ln -sf /usr/X11R6/lib/libXss.a /usr/lib/

export CFLAGS="-Os -fPIC -pipe -L/opt/static" CXXFLAGS="-Os -fPIC -pipe" LDFLAGS="-s -O1 -fPIC -L/opt/static"

cd /usr/src

tar zxf make-3.82.tar.gz
cd /usr/src/make-3.82
./configure; make; make install
export PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:/usr/X11R6/bin/:/
/bin/sh -c "apt-get --force-yes -y remove make << /dev/null"
cd /usr/src

tar zxf zlib-1.2.11.tar.gz
cd /usr/src/zlib-1.2.11
./configure --prefix=/usr --static; make; make install
cd /usr/src

tar zxf openssl*.tar.gz
cd /usr/src/openssl*/
CC="gcc -Os -fPIC" ./Configure --prefix=/usr no-hw-xxx shared \
    no-dso no-err no-krb5 no-hw no-asm no-ssl2 linux-generic32
make depend >/dev/null 2>/dev/null; 
make; make install
cp libssl.so.1.0.0 /usr/lib/libssl.so
cp libcrypto.so.1.0.0  /usr/lib/libcrypto.so
mkdir -p /usr/lib/pkgconfig/
cp *.pc /usr/lib/pkgconfig/
cd /usr/lib
ldconfig -n .
ln -s /usr/lib/libssl.so /usr/lib/libssl.so.1
ln -s /usr/lib/libcrypto.so /usr/lib/libcrypto.so.1
cd /usr/src

tar zxf xz-5.2.2.tar.gz
cd /usr/src/xz-5.2.2
./configure --prefix=/usr; make; make install
cd /usr/src

tar zxf pkg-config-0.29.1.tar.gz
cd /usr/src/pkg-config-0.29.1
./configure --with-internal-glib --prefix=/usr
make install
cd /usr/src

tar zxf libffi_3.2.1.orig.tar.gz
cd /usr/src/libffi-3.2.1
./configure --enable-static --prefix=/usr
make install
cd /usr/src

tar zxf sqlite-autoconf-3150200.tar.gz
cd /usr/src/sqlite-autoconf-3150200
./configure --prefix=/usr --disable-static-shell --disable-dynamic-extensions
make; make install
cd /usr/src

tar zxf Python-2.7.13.tgz
cd /usr/src/Python-2.7.13
./configure --prefix=/usr \
  --without-doc-strings --without-tsc \
  --with-fpectl --with-ensurepip=install --with-signal-module \
  --enable-ipv6 --enable-shared --enable-unicode=ucs4
make; make install
cd /usr/src

xz -d glib-2.32.4.tar.xz
tar xf glib-2.32.4.tar
cd /usr/src/glib-2.32.4
CFLAGS="\$CFLAGS -DPR_SET_NAME=15 -DPR_GET_NAME=16" ./configure \
  --prefix=/usr --disable-xattr --disable-fam --disable-selinux --enable-static
make; make install
cd /usr/src

tar zxf dbus-1.2.12.tar.gz
cd /usr/src/dbus-1.2.12
./configure   --prefix=/usr --disable-selinux --disable-libaudit \
--disable-dnotify --disable-inotify --disable-kqueue \
--disable-userdb-cache --enable-abstract-sockets
make; make install
cd /usr/src

tar zxf dbus-glib-0.88.tar.gz
cd /usr/src/dbus-glib-0.88
./configure --prefix=/usr
make; make install
cd /usr/src

xz -d gobject-introspection-1.32.1.tar.xz
tar xf gobject-introspection-1.32.1.tar
cd /usr/src/gobject-introspection-1.32.1
./configure --prefix=/usr --disable-tests
make; make install
cd /usr/src

tar zxf dbus-python-0.84.0.tar.gz
cd /usr/src/dbus-python-0.84.0
./configure --prefix=/usr
make; make install
cd /usr/src

xz -d pygobject-3.2.2.tar.xz
tar xf pygobject-3.2.2.tar
cd /usr/src/pygobject-3.2.2
./configure --disable-glibtest --disable-cairo \
 --prefix=/usr --enable-static
make -k 
rm -f ./gi/_glib/.libs/libpyglib-gi-2.0-python.so{,.0,.0.0.0}
ln -s libpyglib-gi-2.0-python.a ./gi/_glib/.libs/libpyglib-gi-2.0-python.so
ln -s libpyglib-gi-2.0-python.a ./gi/_glib/.libs/libpyglib-gi-2.0-python.so.0
ln -s libpyglib-gi-2.0-python.a ./gi/_glib/.libs/libpyglib-gi-2.0-python.so.0.0.0
rm -f ./gi/_gi.la ./gi/_gobject/_gobject.la ./gi/_glib/_glib.la
rm -f ./gi/.libs/_gi.la ./gi/_gobject/.libs/_gobject.la ./gi/_glib/.libs/_glib.la
make -k 
make install

cp -vrf /compat/* /usr/include/

cat >>/usr/include/pthread.h <<__EOF__
#ifndef __pthread_condattr_setclock__ 
#define __pthread_condattr_setclock__ 
#define _GNU_SOURCE
#include <dlfcn.h>

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -1l)
#endif

static int (*_pthread_condattr_setclock) (pthread_condattr_t *attr, clockid_t clock_id) = NULL;

static inline
int pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock_id) {
    if (_pthread_condattr_setclock == -1) return -1;
    if (_pthread_condattr_setclock == NULL) _pthread_condattr_setclock = dlsym(
       RTLD_NEXT, "pthread_condattr_setclock");
    if (_pthread_condattr_setclock == NULL) {
        _pthread_condattr_setclock = -1;
        return -1;
    }
}
#endif
__EOF__

python -OO -m pip install --upgrade setuptools
python -OO -m pip install pycparser==2.17
python -OO -m pip install -q six packaging appdirs
python -OO -m pip install -q \
       rpyc pycryptodome pyaml rsa netaddr tinyec pyyaml ecdsa \
       paramiko pylzma pydbus python-ptrace psutil scandir \
       scapy impacket colorama pyOpenSSL \
       --no-binary :all:

/bin/sh -c "apt-get --force-yes -y remove m4 << /dev/null"

cd /usr/src
tar zxf m4-1.4.18.tar.gz
cd /usr/src/m4-1.4.18
./configure --prefix=/usr; make; make install

cd /usr/src
tar zxf autoconf-2.69.tar.gz
cd /usr/src/autoconf-2.69
./configure --prefix=/usr; make; make install

cd /usr/src
tar zxf automake-1.15.tar.gz
cd /usr/src/automake-1.15
./configure --prefix=/usr; make; make install

CFLAGS_PYUV="-O2 -pipe -DCLOCK_MONOTONIC=1 -UHAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC"
CFLAGS_PYUV="\$CFLAGS_PYUV -U_FILE_OFFSET_BITS -D_XOPEN_SOURCE=600 "
CFLAGS_PYUV="\$CFLAGS_PYUV -D_GNU_SOURCE -DS_ISSOCK(m)='(((m) & S_IFMT) == S_IFSOCK)'"

CC=/gccwrap CFLAGS_FILTER="-D_FILE_OFFSET_BITS=64" CFLAGS="\$CFLAGS_PYUV" python -OO -m pip install -q pyuv --no-binary :all:

cd /usr/lib/python2.7
find -name "*.py" | python -m compileall -qfi -
find -name "*.py" | python -OO -m compileall -qfi -

set +x
find -name "*.so" | while read f; do strip \$f; done

cd /

rm -rf /usr/src
apt-get clean

ldconfig
__CMDS__
mkdir -p buildenv/lin32/proc
mkdir -p buildenv/lin32/dev
mount -t proc proc buildenv/lin32/proc
mount -t devtmpfs devtmpfs buildenv/lin32/dev

cp -vfr compat buildenv/lin32/

chroot buildenv/lin32 /bin/bash -x /deploy.sh

umount buildenv/lin32/proc
umount buildenv/lin32/dev

touch buildenv/lin32/.ready

fi

if [ ! -f buildenv/lin64/.ready ]; then
debootstrap --no-check-gpg --arch amd64 etch buildenv/lin64 http://archive.debian.org/debian >/dev/null

mkdir -p buildenv/lin64/usr/src
cp -vfp buildenv/downloads/* buildenv/lin64/usr/src/

mkdir -p buildenv/lin64/etc/ssl/certs
for file in /etc/ssl/certs/*.0; do
    cat $file >buildenv/lin64/etc/ssl/certs/`basename "$file"`
done
cp /etc/ssl/certs/ca-* buildenv/lin64/etc/ssl/certs/

cat /etc/resolv.conf >buildenv/lin64/etc/resolv.conf

cat > buildenv/lin64/wrap.c <<EOF
#define _GNU_SOURCE
#include <sys/utsname.h>
#include <string.h>

static const
struct utsname pupy_utsname = {
  .sysname = "Linux",
  .nodename = "Pupy",
  .release = "2.4.0",
  .version = "2.4.0",
  .machine = "x86_64",
  .domainname = "Pupy",
} ;

int uname(struct utsname *buf) {
    memcpy(buf, &pupy_utsname, sizeof(struct utsname));
    return 0;
}
EOF

cat > buildenv/lin64/gccwrap <<EOF
#!/bin/bash
declare -a filter=( "\$CFLAGS_FILTER" )
declare -a badargs=( "\$CFLAGS_ABORT" )
declare -a outargs=()

for arg; do
  found=false
  for filtered in \${filter[@]}; do
     if [ "\$filtered" == "\$arg" ]; then
        found=true
        break
     fi
  done

  for bad in \${badargs[@]}; do
     if [ "\$bad" == "\$arg" ]; then
        echo "Unsupported argument found: \$bad"
        exit 1
     fi
  done

  if [ "\$found" = "false" ]; then
        outargs[\${#outargs[@]}]="\$arg"
  fi

done

exec gcc "\${outargs[@]}"
EOF

chmod +x buildenv/lin64/gccwrap

cat <<__CMDS__ > buildenv/lin64/deploy.sh

exec 1>/log.txt
set -x

export LC_ALL=C
export MAKEOPTS="-j 2"

useradd -u $XID -m pupy

export TERM=
export DEBIAN_FRONTEND=noninteractive
/bin/sh -c "apt-get --force-yes -y install build-essential make libc-dev \
 perl m4 gettext libexpat1-dev flex bison file libtool patch xutils \
 libx11-dev libxss-dev < /dev/null"

cd /
gcc -fPIC -o /wrap.so -shared /wrap.c
echo /wrap.so >/etc/ld.so.preload

mkdir /opt/static
ln -sf /usr/lib/gcc/x86_64-linux-gnu/4.1.2/libgcc.a /opt/static
ln -sf /usr/lib/gcc/x86_64-linux-gnu/4.1.2/libssp.a /opt/static
ln -sf /usr/lib/gcc/x86_64-linux-gnu/4.1.2/libssp_nonshared.a /opt/static
ln -sf /usr/lib/libffi.a /opt/static/

export CFLAGS="-Os -fPIC -pipe -L/opt/static" CXXFLAGS="-Os -fPIC -pipe" LDFLAGS="-s -O1 -fPIC -L/opt/static"

cd /usr/src

tar zxf make-3.82.tar.gz
cd /usr/src/make-3.82
./configure; make; make install
export PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:/usr/X11R6/bin/:/
/bin/sh -c "apt-get --force-yes -y remove make << /dev/null"
cd /usr/src

tar zxf zlib-1.2.11.tar.gz
cd /usr/src/zlib-1.2.11
./configure --prefix=/usr --static; make; make install
cd /usr/src

tar zxf openssl*.tar.gz
cd /usr/src/openssl*/
CC="gcc -Os -fPIC" ./Configure --prefix=/usr no-hw-xxx shared \
    no-dso no-err no-krb5 no-hw no-asm no-ssl2 linux-generic64
make depend >/dev/null 2>/dev/null
make; make install
cp libssl.so.1.0.0 /usr/lib/libssl.so
cp libcrypto.so.1.0.0  /usr/lib/libcrypto.so
mkdir -p /usr/lib/pkgconfig/
cp *.pc /usr/lib/pkgconfig/
cd /usr/lib
ldconfig -n .
ln -s /usr/lib/libssl.so /usr/lib/libssl.so.1
ln -s /usr/lib/libcrypto.so /usr/lib/libcrypto.so.1
cd /usr/src

tar zxf xz-5.2.2.tar.gz
cd /usr/src/xz-5.2.2
./configure --prefix=/usr; make; make install
cd /usr/src

tar zxf pkg-config-0.29.1.tar.gz
cd /usr/src/pkg-config-0.29.1
./configure --with-internal-glib --prefix=/usr
make install
cd /usr/src

tar zxf libffi_3.2.1.orig.tar.gz
cd /usr/src/libffi-3.2.1
./configure --enable-static --prefix=/usr
make install
cd /usr/src

tar zxf sqlite-autoconf-3150200.tar.gz
cd /usr/src/sqlite-autoconf-3150200
./configure --prefix=/usr --disable-static-shell --disable-dynamic-extensions
make; make install
cd /usr/src

tar zxf Python-2.7.13.tgz
cd /usr/src/Python-2.7.13
./configure --prefix=/usr \
  --without-doc-strings --without-tsc \
  --with-fpectl --with-ensurepip=install --with-signal-module \
  --enable-ipv6 --enable-shared --enable-unicode=ucs4
make; make install
cd /usr/src

xz -d glib-2.32.4.tar.xz
tar xf glib-2.32.4.tar
cd /usr/src/glib-2.32.4
CFLAGS="\$CFLAGS -DPR_SET_NAME=15 -DPR_GET_NAME=16" ./configure \
  --prefix=/usr --disable-xattr --disable-fam --disable-selinux --enable-static
make; make install
cd /usr/src

tar zxf dbus-1.2.12.tar.gz
cd /usr/src/dbus-1.2.12
./configure   --prefix=/usr --disable-selinux --disable-libaudit \
--disable-dnotify --disable-inotify --disable-kqueue \
--disable-userdb-cache --enable-abstract-sockets
make; make install
cd /usr/src

tar zxf dbus-glib-0.88.tar.gz
cd /usr/src/dbus-glib-0.88
./configure --prefix=/usr
make; make install
cd /usr/src

xz -d gobject-introspection-1.32.1.tar.xz
tar xf gobject-introspection-1.32.1.tar
cd /usr/src/gobject-introspection-1.32.1
./configure --prefix=/usr --disable-tests
make; make install
cd /usr/src

tar zxf dbus-python-0.84.0.tar.gz
cd /usr/src/dbus-python-0.84.0
./configure --prefix=/usr
make; make install
cd /usr/src

xz -d pygobject-3.2.2.tar.xz
tar xf pygobject-3.2.2.tar
cd /usr/src/pygobject-3.2.2
./configure --disable-glibtest --disable-cairo \
 --prefix=/usr --enable-static
make -k
rm -f ./gi/_glib/.libs/libpyglib-gi-2.0-python.so{,.0,.0.0.0}
ln -s libpyglib-gi-2.0-python.a ./gi/_glib/.libs/libpyglib-gi-2.0-python.so
ln -s libpyglib-gi-2.0-python.a ./gi/_glib/.libs/libpyglib-gi-2.0-python.so.0
ln -s libpyglib-gi-2.0-python.a ./gi/_glib/.libs/libpyglib-gi-2.0-python.so.0.0.0
rm -f ./gi/_gi.la ./gi/_gobject/_gobject.la ./gi/_glib/_glib.la
rm -f ./gi/.libs/_gi.la ./gi/_gobject/.libs/_gobject.la ./gi/_glib/.libs/_glib.la
make -k
make install

export CFLAGS="$CFLAGS -Os -pipe -U_FORTIFY_SOURCE"
export LDFLAGS="$LDFLAGS"

python -OO -m pip install --upgrade setuptools
python -OO -m pip install pycparser==2.17
python -OO -m pip install -q six packaging appdirs cffi

CC=/gccwrap CFLAGS_ABORT="-D_FORTIFY_SOURCE=2 -fstack-protector" \
 python -OO -m pip install -q pynacl --no-binary :all:

CC=/gccwrap CFLAGS_FILTER="-Wno-error=sign-conversion" \
 python -OO -m pip install -q cryptography --no-binary :all:

python -OO -m pip install -q \
       rpyc pycryptodome pyaml rsa netaddr tinyec pyyaml ecdsa \
       paramiko pylzma pydbus python-ptrace psutil scandir \
       scapy impacket colorama pyOpenSSL \
       --no-binary :all:

/bin/sh -c "apt-get --force-yes -y remove m4 << /dev/null"

cd /usr/src
tar zxf m4-1.4.18.tar.gz
cd /usr/src/m4-1.4.18
./configure --prefix=/usr; make; make install

cd /usr/src
tar zxf autoconf-2.69.tar.gz
cd /usr/src/autoconf-2.69
./configure --prefix=/usr; make; make install

cd /usr/src
tar zxf automake-1.15.tar.gz
cd /usr/src/automake-1.15
./configure --prefix=/usr; make; make install

CFLAGS="\$CFLAGS -D_XOPEN_SOURCE=600 -D_GNU_SOURCE -DS_ISSOCK(m)='(((m) & S_IFMT) == S_IFSOCK)'" \
 python -OO -m pip install -q pyuv --no-binary :all:

cd /usr/lib/python2.7
find -name "*.py" | python -m compileall -qfi -
find -name "*.py" | python -OO -m compileall -qfi -

set +x
find -name "*.so" | while read f; do strip \$f; done

cd /

rm -rf /usr/src
apt-get clean

ldconfig
__CMDS__
mkdir -p buildenv/lin64/proc
mkdir -p buildenv/lin64/dev
mount -t proc proc buildenv/lin64/proc
mount -t devtmpfs devtmpfs buildenv/lin64/dev

chroot buildenv/lin64 /bin/bash -x /deploy.sh

umount buildenv/lin64/proc
umount buildenv/lin64/dev

touch buildenv/lin64/.ready
fi

echo "[+] Creating bundles"

TEMPLATES=`readlink -f ../../pupy/payload_templates`

cd buildenv/lin64/usr/lib/python2.7
rm -f ${TEMPLATES}/linux-amd64.zip
zip -y \
    -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.py" -x "*.pyc" \
    -x "*test/*" -x "*tests/*" -x "*examples/*" \
    -x "*.egg-info/*" -x "*.dist-info/*" \
    -x "idlelib/*" -x "lib-tk/*" -x "tk*"  -x "tcl*" \
    -r9 ${TEMPLATES}/linux-amd64.zip . >/dev/null
cd -

cd buildenv/lin32/usr/lib/python2.7
rm -f ${TEMPLATES}/linux-x86.zip
zip -y \
    -x "*.a" -x "*.o" -x "*.whl" -x "*.txt" -x "*.py" -x "*.pyc" \
    -x "*test/*" -x "*tests/*" -x "*examples/*" \
    -x "*.egg-info/*" -x "*.dist-info/*" \
    -x "idlelib/*" -x "lib-tk/*" -x "tk*"  -x "tcl*" -x "*.la" \
    -r9 ${TEMPLATES}/linux-x86.zip . >/dev/null
cd -

echo "[+] We are done"
