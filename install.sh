#!/bin/bash

# Check to make sure script is not initially run as root
if [ "$EUID" == 0 ]
  then echo "Please do not run as root. Script will prompt for sudo password."
  exit
fi

# Get username for regular user.
username=$(whoami)

# Start root section
sudo su root <<'EOF'

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

# Add user to docker group
usermod -aG docker $username

# End of root section
EOF

# Pull dependencies from github
git submodule update --init --recursive

# Download latest compiled payload templates
wget https://github.com/n1nj4sec/pupy/releases/download/latest/payload_templates.txz
tar xvf payload_templates.txz && mv payload_templates/* pupy/payload_templates/ && rm payload_templates.txz && rm -r payload_templates

# Build docker container
sudo docker pull alxchk/pupy:base-unstable
