#!/bin/bash

# Install TCPReplay according to http://tcpreplay.appneta.com/wiki/installation.html

# Install necessary packages
sudo apt-get install build-essential libpcap-dev nmap

# Download tcpreplay
cd /tmp
wget https://github.com/appneta/tcpreplay/releases/download/v4.1.2/tcpreplay-4.1.2.tar.gz
tar xvf tcpreplay-4.1.2.tar.gz
cd tcpreplay-4.1.2

# Install tcyreplay
./configure --enable-tcpreplay-edit --enable-64bits
make
sudo make install

# Run unit test
sudo make test
