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
apt install python3-pip curl -y
apt-get install libssl-dev swig python3-dev gcc
apt-get install flake8 python3 python2
# Install Docker
apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
apt-get update
apt-get install docker-ce docker-ce-cli containerd.io docker-compose
pip3 install poster3

#Enable docker services
systemctl enable docker.service
systemctl enable containerd.service

# Add user to docker group
groupadd docker
usermod -aG docker $USER



# End of root section
EOF

PYTHON=python

$PYTHON --help >/dev/null
if [ ! $? -eq 0 ]; then
  PYTHON=python3
fi

# Create workspace at ~/pupyws
${PYTHON} create-workspace.py -E docker -P $HOME/pupyws
