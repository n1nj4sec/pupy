#!/bin/bash

# Check if running as root, exit if not
if [ "$EUID" -ne 0 ]
    then echo "ERROR: The install script must be run as root."
    exit
fi

# Apt update and installs
apt update
apt install python-pip curl -y

# Install Docker
curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -

if [ -f /etc/apt/sources.list.d/docker.list ]; then
    echo "Apt source entry exists, skipping."
else
    echo 'deb https://download.docker.com/linux/debian stretch stable' > /etc/apt/sources.list.d/docker.list
fi

apt update
apt-get install docker-ce -y
systemctl start docker
systemctl enable docker

# Install Docker Compose
pip install docker-compose

# Pull dependencies from github
git submodule update --init --recursive

# Download latest compiled payload templates
wget https://github.com/n1nj4sec/pupy/releases/download/latest/payload_templates.txz
tar xvf payload_templates.txz && mv payload_templates/* pupy/payload_templates/ && rm payload_templates.txz && rm -r payload_templates

# Pull docker container
docker pull alxchk/pupy:unstable
