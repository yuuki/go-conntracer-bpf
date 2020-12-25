#!/bin/bash

set -eux

sudo apt-get update
apt-get -y install --no-install-recommends --fix-missing \
    gpg gpg-agent libz-dev libelf-dev ca-certificates \
    git make curl clang llvm build-essential gcc \
    linux-headers-$(uname -r) \
    && apt-get purge --auto-remove && apt-get clean

# Install Go
GOVER='1.15.5'
GOTAR="go${GOVER}.linux-amd64.tar.gz"

wget https://dl.google.com/go/${GOTAR}
sudo tar -C /usr/local -xzf ${GOTAR}
rm -f ${GOTAR}
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

mkdir -p /home/vagrant/go/src/github.com/yuuki/gobpflib-conntracer/

# Install docker
curl -fsSL get.docker.com -o get-docker.sh
sudo /bin/bash get-docker.sh
sudo usermod -aG docker vagrant

echo 'Completed to setup'
