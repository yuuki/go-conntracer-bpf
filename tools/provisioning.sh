#!/bin/bash

set -eux

sudo apt-get -y update
sudo apt-get -y install --no-install-recommends --fix-missing \
    gpg gpg-agent libz-dev libelf-dev ca-certificates \
    git make curl clang llvm build-essential gcc \
    pkg-config \
    linux-headers-$(uname -r)
sudo apt-get purge --auto-remove && sudo apt-get clean

# Support BTF
# sudo apt-get install kernel-package

# Debug Info for libbpf
# U=http://ddebs.ubuntu.com
# D=$(lsb_release -cs)
# cat <<EOF | sudo tee /etc/apt/sources.list.d/ddebs.list
# deb ${U} ${D} main restricted universe multiverse
# #deb ${U} ${D}-security main restricted universe multiverse
# deb ${U} ${D}-updates main restricted universe multiverse
# deb ${U} ${D}-proposed main restricted universe multiverse
# EOF
# wget -O - http://ddebs.ubuntu.com/dbgsym-release-key.asc | \
# sudo apt-key add -
# sudo apt-get update -y
# sudo apt-get install -y linux-image-`uname -r`-dbgsym dwarves
# sudo apt-get purge --auto-remove && sudo apt-get clean

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
