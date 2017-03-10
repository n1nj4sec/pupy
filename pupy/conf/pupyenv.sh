#!/bin/sh

mkdir -p /projects/keys
mkdir -p /projects/hostkeys

chown root /projects/hostkeys
chmod 700 /projects/hostkeys

chown pupy /projects/keys
chmod 700 /projects/keys

if [ ! -f /projects/hostkeys/ssh_host_rsa_key ]; then
    ssh-keygen -f /projects/hostkeys/ssh_host_rsa_key -N '' -t rsa
fi

if [ ! -f /projects/hostkeys/ssh_host_dsa_key ]; then
    ssh-keygen -f /projects/hostkeys/ssh_host_dsa_key -N '' -t dsa
fi

if [ ! -f /projects/hostkeys/ssh_host_ecdsa_key ]; then
    ssh-keygen -f /projects/hostkeys/ssh_host_ecdsa_key -N '' -t ecdsa
fi

if [ ! -f /projects/hostkeys/ssh_host_ed25519_key ]; then
    ssh-keygen -f /projects/hostkeys/ssh_host_ed25519_key -N '' -t ed25519
fi

for k in /projects/hostkeys/*; do
    cp -af $k /etc/ssh/
done

if [ ! -d "/projects/$1" ]; then
    mkdir -p "/projects/$1"
    chown pupy "/projects/$1"
fi

echo "$1" >/home/pupy/.project

cd /opt/pupy

python -m compileall -q >/dev/null

echo 'Copy your authorized_keys here!' >/projects/keys/README

cat >>/projects/README <<__EOF__
SSH user: pupy
Port:     22

cp ~/.ssh/authorized_keys /projects/keys/authorized_keys

Example:

mkdir /tmp/projects/keys
cp ~/.ssh/authorized_keys /projects/keys/authorized_keys
docker run -D -p 2022:22 -p 9999:9999 -v /tmp/projects:/projects pupy:latest
ssh -p 2022 pupy@127.0.0.1
__EOF__

/usr/sbin/sshd -D
