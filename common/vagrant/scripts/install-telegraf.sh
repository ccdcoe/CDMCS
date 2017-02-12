#!/bin/bash
#
# this script
# 1) installs telegraf
# 2) sets influxdb to $1

#set telegraf version here
TELEGRAF="telegraf_1.2.1_amd64.deb"

if [ "$(id -u)" != "0" ]; then
   echo "ERROR - This script must be run as root" 1>&2
   exit 1
fi

function error_exit
{
  echo "$1"
  exit 1
}

[[ -z $1 ]] && error_exit "no param, can not set influxdb"

function jab
{
  if [ ! $(ping -c1 "$1" | tail -2| head -1 | grep "1 packets transmitted, 1 received, 0% packet loss, time 0ms" | wc -l) -eq 1 ];
  then
    echo "warning, ping failed on $1"
  fi
}

INFLUXDB=$1
IP=$(ifconfig eth0 2>/dev/null|grep 'inet addr'|cut -f2 -d':'|cut -f1 -d' ')
HOSTNAME=$(hostname -f)

echo "installing telegraf on ${IP} ${HOSTNAME} setting influxdb to ${INFLUXDB} ..."
jab "${INFLUXDB}"

echo "LC_ALL=en_US.UTF-8" >> /etc/environment
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4


cd /vagrant
[[ -f $TELEGRAF ]] || time wget  -q -4 https://dl.influxdata.com/telegraf/releases/$TELEGRAF
dpkg -i $TELEGRAF > /dev/null 2>&1
cat >> /etc/telegraf/telegraf.conf <<EOF
[[inputs.net]]
[[inputs.netstat]]
[[inputs.nginx]]
  urls = ["http://localhost/status"]
EOF
service telegraf start
