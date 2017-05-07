#!/bin/bash
#
# it will build, install and configure Moloch
#

if [ "$(id -u)" != "0" ]; then
   echo "ERROR - This script must be run as root" 1>&2
   exit 1
fi

start=$(date)
echo $start >  /vagrant/provision.log
echo "Installing prerequisite standard packages..."
echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4
export DEBIAN_FRONTEND=noninteractive
apt-get -y install wget curl libpcre3-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev >> /vagrant/provision.log 2>&1
echo "installing node v4.6.0...."
# see https://github.com/aol/moloch#building-viewer
apt-get -y install python-minimal >> /vagrant/provision.log 2>&1
cd /tmp
wget -q -4 wget https://nodejs.org/dist/v4.6.0/node-v4.6.0-linux-x64.tar.xz
tar -xf node-v4.6.0-linux-x64.tar.xz
mv node-v4.6.0-linux-x64 /opt/
ln -s /opt/node-v4.6.0-linux-x64/bin/node /usr/local/bin/node
ln -s /opt/node-v4.6.0-linux-x64/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm

echo "getting moloch source..."
cd /tmp
wget -q -4 https://github.com/aol/moloch/archive/master.tar.gz
tar -xf master.tar.gz
echo "building moloch..."
cd moloch-master/
./easybutton-build.sh >> /vagrant/provision.log 2>&1
make install >> /vagrant/provision.log 2>&1
echo -en "enp0s3;enp0s8;\nno\nhttp://localhost:9200\ns2spassword\n" | make config >> /vagrant/provision.log 2>&1
echo "testing moloch..."
/data/moloch/bin/moloch-capture --nospi
