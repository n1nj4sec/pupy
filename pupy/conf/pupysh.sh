#!/bin/sh

if [ ! -f /project/config/pupy.conf ]; then
    echo "[+] Copy default configuration to config/pupy.conf"
    mkdir -p /project/config/
    cp -f /opt/pupy/conf/pupy.conf.docker /project/config/pupy.conf
fi

for dir in data crypto output; do
    if [ ! -d /project/$dir ]; then
	mkdir /project/$dir
    fi
done

cd /project

exec /opt/pupy/pupysh.py
