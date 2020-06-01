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

# Add user to docker group
usermod -aG docker $username

# End of root section
EOF

PYTHON=python

$PYTHON --help >/dev/null
if [ ! $? -eq 0 ]; then
  PYTHON=python3
fi

# Create workspace at ~/pupyws
${PYTHON} create-workspace.py -E docker -P $HOME/pupyws
