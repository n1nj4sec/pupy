#!/bin/sh

THIS_FILE=`readlink -f $0`
THIS_DIR=`dirname ${THIS_FILE}`

cd ${THIS_DIR}/pupy

apt update
pkg upgrade -y

pkg install -y python2-dev curl clang libcrypt-dev libffi-dev openssl-dev \
    automake autoconf libtool make pkg-config libuv-dev

ln -fs /data/data/com.termux/files/usr/bin/python2 /data/data/com.termux/files/usr/bin/python
ln -fs /data/data/com.termux/files/usr/bin/pip2 /data/data/com.termux/files/usr/bin/pip


python2 -m pip install --global-option 'build_ext' --global-option '--use-system-libuv' pyuv
python2 -m pip install -r requirements.txt
python2 -m pip install --upgrade --force-reinstall pycryptodome

mkdir -p ~/netbase/wireshark/share/wireshark

curl -L http://http.debian.net/debian/pool/main/n/netbase/netbase_5.4.tar.xz | \
    tar -C ~/netbase -Jxf -
curl -qL 'https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf' \
     > ~/netbase/wireshark/share/wireshark/manuf

for f in protocols ethertypes services; do
    sed -i /data/data/com.termux/files/usr/lib/python2.7/site-packages/scapy/data.py \
	-e "s@/etc/$f@/data/data/com.termux/files/home/netbase/netbase-5.4/etc-$f@g"
done

sed -i /data/data/com.termux/files/usr/lib/python2.7/site-packages/scapy/data.py \
    -e 's@/opt/wireshark@/data/data/com.termux/files/home/netbase/wireshark@g'
