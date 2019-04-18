PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"

DOCKER_ELA="docker.elastic.co/elasticsearch/elasticsearch-oss:6.7.0"
MOLOCH="moloch_1.8.0-1_amd64.deb"
USER="vagrant"

if [[ -n $(ip link show | grep eth0) ]]; then
  IFACE_EXT="eth0"
  IFACE_INT="eth1"
  IFACE_PATTERN="eth"
else
  IFACE_EXT="enp0s3"
  IFACE_INT="enp0s8"
  IFACE_PATTERN="enp"
fi

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
grep "vm.max_map_count" $FILE || cat >> $FILE <<EOF
vm.max_map_count=262144
EOF
sysctl -p

echo $start >  /vagrant/provision.log
echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4
export DEBIAN_FRONTEND=noninteractive

echo "Installing prerequisite packages..."
apt-get update && apt-get -y install jq wget curl pcregrep python-minimal python-pip python3-pip python-yaml libpcre3-dev libyaml-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev libsnappy-dev numactl >> /vagrant/provision.log 2>&1

docker network ls | grep cdmcs >/dev/null || docker network create -d bridge cdmcs

docker ps -a | grep elastic || docker run -dit --name elastic -h elastic --network cdmcs -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" --restart unless-stopped -p 9200:9200 $DOCKER_ELA 
sleep 10

echo "Provision moloch"
cd $PKGDIR
[[ -f $MOLOCH ]] || wget $WGET_PARAMS https://files.molo.ch/builds/ubuntu-18.04/$MOLOCH
dpkg -s moloch || dpkg -i $MOLOCH

echo "Configuring interfaces"
for iface in ${ifaces//;/ }; do
  echo "Setting capture params for $iface"
  for i in rx tx tso gso gro tx nocache copy sg rxvlan; do ethtool -K $iface $i off > /dev/null 2>&1; done
done

echo "Configuring moloch"
delim=";"; ifaces=""; for item in `ls /sys/class/net/ | egrep '^eth|ens|eno|enp'`; do ifaces+="$item$delim"; done ; ifaces=${ifaces%"$deli$delim"}
cd /data/moloch/etc
FILE=/data/moloch/etc/config.ini
[[ -f config.ini ]] || cp config.ini.sample $FILE
sed -i "s/MOLOCH_ELASTICSEARCH/localhost:9200/g"  config.ini
sed -i "s/MOLOCH_INTERFACE/$ifaces/g"             config.ini
sed -i "s/MOLOCH_INSTALL_DIR/\/data\/moloch/g"    config.ini
sed -i "s/MOLOCH_INSTALL_DIR/\/data\/moloch/g"    config.ini
sed -i "s/MOLOCH_PASSWORD/test123/g"              config.ini

echo "Configuring databases"
cd /data/moloch/db
if [[ `./db.pl localhost:9200 info | grep "DB Version" | cut -d ":" -f2 | tr -d " "` -eq -1 ]]; then
  echo "INIT" | ./db.pl localhost:9200 init
fi

cd /data/moloch/bin
./moloch_update_geo.sh > /dev/null 2>&1
chown nobody:daemon /data/moloch/raw

echo "Adding viewer user"
cd /data/moloch/viewer && ../bin/node addUser.js vagrant vagrant vagrant --admin

echo "Configuring system limits"
ulimit -l unlimited
grep memlock /etc/security/limits.conf || echo "nofile 128000 - memlock unlimited" >> /etc/security/limits.conf
mkdir /data/moloch/raw && chown nobody:daemon /data/moloch/raw

echo "Configuring systemd services"

FILE=/etc/systemd/system/moloch-viewer.service
grep "moloch-viewer" $FILE || cat > $FILE <<EOF
[Unit]
Description=Moloch Viewer
After=network.target moloch-wise.service

[Service]
Type=simple
Restart=on-failure
ExecStart=/data/moloch/bin/node viewer.js -c /data/moloch/etc/config.ini
WorkingDirectory=/data/moloch/viewer
SyslogIdentifier=moloch-viewer

[Install]
WantedBy=multi-user.target
EOF

FILE=/etc/systemd/system/moloch-capture.service
grep "moloch-capture" $FILE || cat > $FILE <<EOF
PIDFILE=/var/run/capture.pid
[Unit]
Description=Moloch Capture
After=network.target moloch-wise.service moloch-viewer.service

[Service]
Type=simple
Restart=on-failure
#ExecStartPre=-/data/moloch/bin/start-capture-interfaces.sh
ExecStart=/usr/bin/numactl --cpunodebind=0 --membind=0 /data/moloch/bin/moloch-capture -c /data/moloch/etc/config.ini --host $(hostname)
WorkingDirectory=/data/moloch
LimitCORE=infinity
LimitMEMLOCK=infinity
SyslogIdentifier=moloch-capture

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
for service in viewer capture ; do
  systemctl enable moloch-$service.service
  systemctl start moloch-$service.service
  systemctl status moloch-$service.service
done

echo "making some noise"
while : ; do curl -s https://www.facebook.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s https://sysadminnid.tumblr.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s http://testmyids.com > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s -k https://self-signed.badssl.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do dig NS berylia.org @1.1.1.1 > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do dig NS berylia.org @8.8.8.8 > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
