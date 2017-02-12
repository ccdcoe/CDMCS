#!/bin/bash
#
# this script
# 1) installs salt-minion
# 2) sets master to $1

if [ "$(id -u)" != "0" ]; then
   echo "ERROR - This script must be run as root" 1>&2
   exit 1
fi

function error_exit
{
  echo "$1"
  exit 1
}

[[ -z $1 ]] && error_exit "no param, can not set salt-master"

function jab
{
  if [ ! $(ping -c1 "$1" | tail -2| head -1 | grep "1 packets transmitted, 1 received, 0% packet loss" | wc -l) -eq 1 ];
  then
    echo "warning, ping failed on $1"
  fi
}

MASTER=$1
IP=$(ifconfig eth0 2>/dev/null|grep 'inet addr'|cut -f2 -d':'|cut -f1 -d' ')
HOSTNAME=$(hostname -f)

echo "installing salt-minion on ${IP} ${HOSTNAME} setting master to ${MASTER}..."
jab "${MASTER}"

echo "LC_ALL=en_US.UTF-8" >> /etc/environment
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

#add-apt-repository -y ppa:saltstack/salt > /dev/null 2>&1
#apt-get update  > /dev/null 2>&1
apt-get -y install salt-minion  > /dev/null 2>&1
systemctl stop salt-minion 
systemctl enable salt-minion
salt-minion --version
mv /etc/salt/minion /etc/salt/minion.from_package
echo "master: ${MASTER}" > /etc/salt/minion
echo "hash_type: sha256" >> /etc/salt/minion
echo "${MASTER} salt" >> /etc/hosts
systemctl start salt-minion
sleep 1
tail /var/log/salt/minion
