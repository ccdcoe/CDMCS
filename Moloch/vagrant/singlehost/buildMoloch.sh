#!/bin/bash
#
# it will build, install and configure Moloch as regular user
# https://github.com/npm/npm/issues/19883

VER=$1
ME=$(whoami)

if ! grep -q "moloch-$VER" $HOME/.bashrc; then
  echo "export PATH=\"$PATH:$HOME/moloch-$VER/bin\"" >> $HOME/.bashrc
fi
if ! echo $PATH | grep -q "moloch-$VER"; then
  export PATH="$PATH:$HOME/moloch-$VER/bin"
fi

echo "Pulling moloch"
[[ -d $HOME/moloch-build ]] || git clone https://github.com/aol/moloch $HOME/moloch-build
cd $HOME/moloch-build
git checkout tags/$VER

echo "Building"
./easybutton-build.sh -d $HOME/moloch-$VER >> /vagrant/provision.log 2>&1
sudo chown -R $ME $HOME/moloch-$VER

echo "Installing"
make install >> /vagrant/provision.log 2>&1
