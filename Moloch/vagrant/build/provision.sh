#!/bin/bash
#
# it will set up system-wide prereqs to build and configure moloch as regular user
#

MOLOVER="v1.1.0"
USER="vagrant"

if [ "$(id -u)" != "0" ]; then
   echo "ERROR - This script must be run as root" 1>&2
   exit 1
fi

start=$(date)
echo $start >  /vagrant/provision.log
echo "Installing prerequisite packages..."
echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get -y install wget curl python-minimal libpcre3-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev >> /vagrant/provision.log 2>&1

echo "Provision moloch $MOLOVER as $USER"
cp /vagrant/buildMoloch.sh /home/$USER/buildMoloch.sh && chown $USER /home/$USER/buildMoloch.sh
time su -c "bash /home/$USER/buildMoloch.sh $MOLOVER" $USER

echo "DONE :: start $start end $(date)"
