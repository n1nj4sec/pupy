#!/bin/sh

export XID=`id -u`

# VERSIONS /MAY/ BE UPDATED (In case of vulnerabilites)
OPENSSL_SRC="http://http.debian.net/debian/pool/main/o/openssl/openssl_1.0.2j.orig.tar.gz"
ZLIB_SRC="http://zlib.net/zlib-1.2.8.tar.gz"
SQLITE_SRC="http://www.sqlite.org/2016/sqlite-autoconf-3150200.tar.gz"
LIBFFI_SRC="http://http.debian.net/debian/pool/main/libf/libffi/libffi_3.2.1.orig.tar.gz"
PYTHON_SRC="https://www.python.org/ftp/python/2.7.12/Python-2.7.12.tgz"
PKGCONFIG_SRC="https://pkg-config.freedesktop.org/releases/pkg-config-0.29.1.tar.gz"
XZ_SRC="http://tukaani.org/xz/xz-5.2.2.tar.gz"

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
                           "$PYGOBJECT" "$DBUS_PYTHON"; do
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

debootstrap --arch i386 woody buildenv/lin32 http://archive.debian.org/debian
mkdir -p buildenv/lin32/usr/src
cp -vfp buildenv/downloads/* buildenv/lin32/usr/src/

mkdir -p buildenv/lin32/etc/ssl/certs
for file in /etc/ssl/certs/*.0; do
    cat $file >buildenv/lin32/etc/ssl/certs/`basename "$file"`
done

cat /etc/resolv.conf >buildenv/lin32/etc/resolv.conf

cat > buildenv/lin32/wrap.c <<EOF
#define _GNU_SOURCE
#include <sys/utsname.h>

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

cat <<__CMDS__ > buildenv/lin32/deploy.sh

exec 2>/log.txt

export LC_ALL=C

useradd -u $XID -m pupy

export TERM=
export DEBIAN_FRONTEND=noninteractive
/bin/sh -c "apt-get --force-yes -y install gcc-3.0 make libc-dev \
 perl m4 gettext libexpat1-dev flex bison file libstdc++2.10-dev < /dev/null"

cd /
gcc -fPIC -o /wrap.so -shared /wrap.c
echo /wrap.so >/etc/ld.so.preload

mkdir /opt/static
ln -sf /usr/lib/gcc-lib/i386-linux/3.0.4/libgcc.a /opt/static/
ln -sf /usr/lib/libffi.a /opt/static/
ln -sf /usr/lib/libutil.a /opt/static/
ln -sf /usr/bin/gcc-3.0 /usr/bin/gcc
ln -sf /usr/bin/gcc-3.0 /usr/bin/cc

export CFLAGS="-Os -fPIC -pipe -L/opt/static" CXXFLAGS="-Os -fPIC -pipe" LDFLAGS="-s -O1 -fPIC -L/opt/static"

cd /usr/src

tar zxf make-3.82.tar.gz
cd /usr/src/make-3.82
./configure; make; make install
export PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin
/bin/sh -c "apt-get --force-yes -y remove make << /dev/null"
cd /usr/src

tar zxf zlib-1.2.8.tar.gz
cd /usr/src/zlib-1.2.8
./configure --prefix=/usr --static; make; make install
cd /usr/src

tar zxf openssl_1.0.2j.orig.tar.gz
cd /usr/src/openssl-1.0.2j/
CC="gcc -Os -fPIC" ./Configure --prefix=/usr no-hw-xxx no-shared \
    no-dso no-krb5 no-hw no-asm no-ssl2 linux-generic32
make depend; make; make install
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

tar zxf Python-2.7.12.tgz
cd /usr/src/Python-2.7.12
./configure --prefix=/usr \
  --without-doc-strings --without-tsc --without-pymalloc \
  --with-fpectl --with-ensurepip=install --with-signal-module \
  --enable-ipv6 --enable-shared
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

python -OO -m pip install \
       rpyc pycrypto pyaml rsa netaddr tinyec pyyaml ecdsa \
       paramiko uptime pylzma pydbus python-ptrace psutil \
       --upgrade --no-binary :all:

cd /usr/lib/python2.7
python -OO -m compileall

find -name "*.so" | while read f; do strip $f; done

cd /

rm -rf /usr/src

ldconfig
__CMDS__

mount -t proc proc buildenv/lin32/proc
mount -t devtmpfs devtmpfs buildenv/lin32/dev

cp -vfr compat buildenv/lin32/

chroot buildenv/lin32 /bin/bash -x /deploy.sh

umount buildenv/lin32/proc
umount buildenv/lin32/dev

touch buildenv/lin32/.ready

fi

if [ ! -f buildenv/lin64/.ready ]; then
debootstrap --no-check-gpg --arch amd64 etch buildenv/lin64 http://archive.debian.org/debian

mkdir -p buildenv/lin64/usr/src
cp -vfp buildenv/downloads/* buildenv/lin64/usr/src/

mkdir -p buildenv/lin64/etc/ssl/certs
for file in /etc/ssl/certs/*.0; do
    cat $file >buildenv/lin64/etc/ssl/certs/`basename "$file"`
done

cat /etc/resolv.conf >buildenv/lin64/etc/resolv.conf

cat > buildenv/lin64/wrap.c <<EOF
#define _GNU_SOURCE
#include <sys/utsname.h>

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

cat <<__CMDS__ > buildenv/lin64/deploy.sh

exec 2>/log.txt

export LC_ALL=C

useradd -u $XID -m pupy

export TERM=
export DEBIAN_FRONTEND=noninteractive
/bin/sh -c "apt-get --force-yes -y install build-essential make libc-dev \
 perl m4 gettext libexpat1-dev flex bison file < /dev/null"

cd /
gcc -fPIC -o /wrap.so -shared /wrap.c
echo /wrap.so >/etc/ld.so.preload

mkdir /opt/static
ln -sf /usr/lib/gcc/x86_64-linux-gnu/4.1.2/libgcc.a /opt/static
ln -sf /usr/lib/libffi.a /opt/static/

export CFLAGS="-Os -fPIC -pipe -L/opt/static" CXXFLAGS="-Os -fPIC -pipe" LDFLAGS="-s -O1 -fPIC -L/opt/static"

cd /usr/src

tar zxf make-3.82.tar.gz
cd /usr/src/make-3.82
./configure; make; make install
export PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin
/bin/sh -c "apt-get --force-yes -y remove make << /dev/null"
cd /usr/src

tar zxf zlib-1.2.8.tar.gz
cd /usr/src/zlib-1.2.8
./configure --prefix=/usr --static; make; make install
cd /usr/src

tar zxf openssl_1.0.2j.orig.tar.gz
cd /usr/src/openssl-1.0.2j/
CC="gcc -Os -fPIC" ./Configure --prefix=/usr no-hw-xxx no-shared \
    no-dso no-krb5 no-hw no-asm no-ssl2 linux-generic64
make depend; make; make install
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

tar zxf Python-2.7.12.tgz
cd /usr/src/Python-2.7.12
./configure --prefix=/usr \
  --without-doc-strings --without-tsc --without-pymalloc \
  --with-fpectl --with-ensurepip=install --with-signal-module \
  --enable-ipv6 --enable-shared
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

python -OO -m pip install \
       rpyc pycrypto pyaml rsa netaddr tinyec pyyaml ecdsa \
       paramiko uptime pylzma pydbus python-ptrace psutil \
       --upgrade --no-binary :all:

cd /usr/lib/python2.7
python -OO -m compileall

find -name "*.so" | while read f; do strip $f; done

cd /

rm -rf /usr/src

ldconfig
__CMDS__

mount -t proc proc buildenv/lin64/proc
mount -t devtmpfs devtmpfs buildenv/lin64/dev

chroot buildenv/lin64 /bin/bash -x /deploy.sh

umount buildenv/lin64/proc
umount buildenv/lin64/dev

touch buildenv/lin64/.ready
fi

echo "[+] We are done"
