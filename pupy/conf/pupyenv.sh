#!/bin/sh

mkdir -p /home/pupy/projects/keys
mkdir -p /home/pupy/projects/hostkeys

chown root /home/pupy/projects/hostkeys
chmod 700 /home/pupy/projects/hostkeys

chown pupy /home/pupy/projects/keys
chmod 700 /home/pupy/projects/keys

if [ ! -f /home/pupy/projects/hostkeys/ssh_host_rsa_key ]; then
    ssh-keygen -f /home/pupy/projects/hostkeys/ssh_host_rsa_key -N '' -t rsa
fi

if [ ! -f /home/pupy/projects/hostkeys/ssh_host_dsa_key ]; then
    ssh-keygen -f /home/pupy/projects/hostkeys/ssh_host_dsa_key -N '' -t dsa
fi

if [ ! -f /home/pupy/projects/hostkeys/ssh_host_ecdsa_key ]; then
    ssh-keygen -f /home/pupy/projects/hostkeys/ssh_host_ecdsa_key -N '' -t ecdsa
fi

if [ ! -f /home/pupy/projects/hostkeys/ssh_host_ed25519_key ]; then
    ssh-keygen -f /home/pupy/projects/hostkeys/ssh_host_ed25519_key -N '' -t ed25519
fi

for k in /home/pupy/projects/hostkeys/*; do
    cp -af $k /etc/ssh/
done

if [ ! -d "/home/pupy/projects/$1" ]; then
    mkdir -p "/home/pupy/projects/$1"
    chown pupy "/home/pupy/projects/$1"
fi

cd /opt/pupy

python -m compileall

echo 'Copy your authorized_keys here!' >/home/pupy/projects/keys/README

/usr/sbin/sshd -D
