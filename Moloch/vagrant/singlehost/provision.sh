#!/bin/bash
#
# it will set up system-wide prereqs to build and configure moloch as regular user
#

check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive|failed" && systemctl start $1.service
  systemctl status $1.service
}

# params
DEBUG=true
PROXY=http://192.168.10.1:3128
EXPOSE=192.168.10.11
PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"

# versions
ELA="elasticsearch-6.2.3.deb"
KIBANA="kibana-6.2.3-amd64.deb"
INFLUX="influxdb_1.5.1_amd64.deb"
TELEGRAF="telegraf_1.5.3-1_amd64.deb"
GRAFANA="grafana_5.0.4_amd64.deb"

MOLOCH="moloch_1.0.0-1_amd64.deb"
#MOLOCH="v1.0.0-rc2"
USER="vagrant"

mkdir -p $PKGDIR

if [ "$(id -u)" != "0" ]; then
   echo "ERROR - This script must be run as root" 1>&2
   exit 1
fi

start=$(date)
# basic OS config
FILE=/etc/sysctl.conf
grep "disable_ipv6" $FILE || cat >> $FILE <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p

echo $start >  /vagrant/provision.log
echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4
export DEBIAN_FRONTEND=noninteractive

echo "Installing prerequisite packages..."
apt-get update && apt-get -y install wget curl python-minimal libpcre3-dev libyaml-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev >> /vagrant/provision.log 2>&1

#FILE=/etc/profile
#grep "proxy" $FILE || cat >> $FILE <<EOF
#http_proxy=$PROXY
#https_proxy=$PROXY
#export http_proxy
#export https_proxy
#EOF
#source /etc/profile

# java
install_oracle_java() {
  echo "Installing oracle Java"
  echo 'oracle-java8-installer shared/accepted-oracle-license-v1-1 boolean true' | debconf-set-selections \
  && add-apt-repository ppa:webupd8team/java \
  && apt-get update > /dev/null \
  && apt-get -y install oracle-java8-installer > /dev/null
}
echo "Provisioning JAVA"
# https://askubuntu.com/questions/966107/cant-install-oracle-java-8-in-ubuntu-16-04
# java -version || install_oracle_java
#apt-get update
java -version || apt-get install -y openjdk-8-jre-headless

# elastic
echo "Provisioning ELASTICSEARCH"
cd $PKGDIR
[[ -f $ELA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/elasticsearch/$ELA -O $ELA
dpkg -s elasticsearch || dpkg -i $ELA > /dev/null 2>&1

check_service elasticsearch

# kibana
echo "Provisioning KIBANA"
cd $PKGDIR
[[ -f $KIBANA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/kibana/$KIBANA -O $KIBANA
dpkg -s kibana || dpkg -i $KIBANA > /dev/null 2>&1

FILE=/etc/kibana/kibana.yml
grep "provisioned" $FILE || cat >> $FILE <<EOF
# provisioned
server.host: "0.0.0.0"
EOF

check_service kibana

echo "Provision moloch"
#cp /vagrant/buildMoloch.sh /home/$USER/buildMoloch.sh && chown $USER /home/$USER/buildMoloch.sh
#[[ -f /home/$USER/moloch-$MOLOCH/bin/moloch-capture ]] || time su -c "bash /home/$USER/buildMoloch.sh $MOLOCH" $USER
cd $PKGDIR
[[ -f $MOLOCH ]] || wget $WGET_PARAMS https://files.molo.ch/builds/ubuntu-16.04/$MOLOCH
dpkg -s moloch || dpkg -i $MOLOCH

echo "Configuring moloch"
cd /data/moloch/etc
[[ -f config.ini ]] || cp config.ini.sample config.ini
sed -i "s/MOLOCH_ELASTICSEARCH/localhost:9200/g"  config.ini
sed -i "s/MOLOCH_INTERFACE/enp3s0/g"              config.ini
sed -i "s/MOLOCH_INSTALL_DIR/\/data\/moloch/g"    config.ini
sed -i "s/MOLOCH_INSTALL_DIR/\/data\/moloch/g"    config.ini
sed -i "s/MOLOCH_PASSWORD/test123/g"              config.ini

cd /data/moloch/db
if [[ `./db.pl localhost:9200 info | grep "DB Version" | cut -d ":" -f2 | tr -d " "` -eq -1 ]]; then
  echo "y" | ./db.pl localhost:9200 init
fi

echo "DONE :: start $start end $(date)"
