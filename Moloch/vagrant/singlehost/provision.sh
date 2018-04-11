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
PATH=$PATH:/data/moloch/bin

grep PATH /home/vagrant/.bashrc || echo 'PATH=$PATH:/data/moloch/bin' >> /home/vagrant/.bashrc
grep PATH /root/.bashrc || echo 'PATH=$PATH:/data/moloch/bin' >> /root/.bashrc

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

#which docker && docker run -dit --restart unless-stopped -p 127.0.0.1:6379:6379 --name redis0 redis
which docker && docker run -dit --restart unless-stopped -p 6379:6379 --name redis0 redis

echo "Installing prerequisite packages..."
apt-get update && apt-get -y install wget curl python-minimal python-pip python-yaml libpcre3-dev libyaml-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev >> /vagrant/provision.log 2>&1

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
delim=";"; ifaces=""; for item in `ls /sys/class/net/ | egrep '^eth|ens|eno|enp'`; do ifaces+="$item$delim"; done ; ifaces=${ifaces%"$deli$delim"}
cd /data/moloch/etc
[[ -f config.ini ]] || cp config.ini.sample config.ini
sed -i "s/MOLOCH_ELASTICSEARCH/localhost:9200/g"  config.ini
sed -i "s/MOLOCH_INTERFACE/$ifaces/g"             config.ini
sed -i "s/MOLOCH_INSTALL_DIR/\/data\/moloch/g"    config.ini
sed -i "s/MOLOCH_INSTALL_DIR/\/data\/moloch/g"    config.ini
sed -i "s/MOLOCH_PASSWORD/test123/g"              config.ini

echo "Configuring wise"
cp wise.ini.sample wiseService.ini
sed -i -e 's,#wiseHost=127.0.0.1,wiseHost=127.0.0.1\nplugins=wise.so\nviewerPlugins=wise.js\nwiseTcpTupleLookups=true\nwiseUdpTupleLookups=true\n,g' config.ini
grep CDMCS wiseService.ini || cat >> wiseService.ini <<EOF
# CDMCS
[reversedns]
ips=10.0.0.0/8
field=asset

[cache]
type=redis
url=redis://127.0.0.1:6379/1
EOF

echo "Configuring databases"
cd /data/moloch/db
if [[ `./db.pl localhost:9200 info | grep "DB Version" | cut -d ":" -f2 | tr -d " "` -eq -1 ]]; then
  echo "y" | ./db.pl localhost:9200 init
fi
cd /data/moloch/bin
./moloch_update_geo.sh > /dev/null 2>&1
chown nobody:daemon /data/moloch/raw

echo "Configuring interfaces"
for iface in ${ifaces//;/ }; do
  echo "Setting capture params for $iface"
  for i in rx tx tso gso gro tx nocache copy sg rxvlan; do ethtool -K $iface $i off > /dev/null 2>&1; done
done

echo "Starting up wise"
cd /data/moloch/wiseService
PIDFILE=/var/run/wise.pid
[[ -f $PIDFILE ]] || nohup node wiseService.js > >(logger -p daemon.info -t wise) 2> >(logger -p daemon.err -t wise) & sleep 1 ; echo $! > $PIDFILE

echo "Starting up capture"
PIDFILE=/var/run/capture.pid
[[ -f $PIDFILE ]] || nohup moloch-capture -c /data/moloch/etc/config.ini > >(logger -p daemon.info -t capture) 2> >(logger -p daemon.err -t capture) & sleep 1 ; echo $! > $PIDFILE
sleep 2 && egrep "capture:.+ERROR" /var/log/syslog

echo "Starting up viewer"
cd /data/moloch/viewer
PIDFILE=/var/run/viewer.pid
node addUser.js vagrant vagrant vagrant --admin
[[ -f $PIDFILE ]] || nohup node viewer.js -c ../etc/config.ini > >(logger -p daemon.info -t viewer) 2> >(logger -p daemon.err -t viewer) & sleep 1 ; echo $! > $PIDFILE
sleep 2 && egrep "viewer:.+ERROR" /var/log/syslog

# suricata
install_suricata_from_ppa(){
  add-apt-repository ppa:oisf/suricata-stable > /dev/null 2>&1 \
  && apt-get update > /dev/null \
  && apt-get install -y suricata > /dev/null
}
echo "Provisioning Suricata"
suricata -V || install_suricata_from_ppa
systemctl stop suricata

touch  /etc/suricata/threshold.config

FILE=/etc/suricata/suricata.yaml
grep "cdmcs" $FILE || cat >> $FILE <<EOF
include: /etc/suricata/cdmcs-detect.yaml
include: /etc/suricata/cdmcs-logging.yaml
EOF

touch /var/lib/suricata/rules/suricata.rules
FILE=/etc/suricata/cdmcs-detect.yaml
grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
af-packet:
  - interface: `echo $ifaces | cut -d";" -f1`
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: `echo $ifaces | cut -d";" -f2`
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: /etc/suricata/rules
rule-files:
 - /var/lib/suricata/rules/suricata.rules
sensor-name: CDMCS
EOF

FILE=/etc/suricata/cdmcs-logging.yaml
grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: 'yes'
      filetype: redis
      filename: eve.json
      redis:
        server: 127.0.0.1
        key: suricata
        port: 6379
        async: true
        mode: list
        pipelining:
          enabled: yes
          batch-size: 10

      types:
        - alert:
            metadata: yes
            tagged-packets: yes
            xff:
              enabled: no
              mode: extra-data
              deployment: reverse
              header: X-Forwarded-For
#        - http:
#            extended: yes
#        - dns:
#            query: yes
#            answer: yes
#        - tls:
#            extended: yes
#        - files:
#            force-magic: no
#        - smtp:
#        - ssh
#        - stats:
#            totals: yes
#            threads: no
#            deltas: no
#        - flow
EOF
grep DC_SERVERS /etc/suricata/suricata.yaml || sed -i '/ENIP_SERVER/a\ \ \ \ DC_SERVERS: "[192.168.10.250/32]"' /etc/suricata/suricata.yaml

[[ -f /etc/init.d/suricata ]] && rm /etc/init.d/suricata
FILE=/etc/systemd/system/suricata.service
grep "suricata" $FILE || cat > $FILE <<EOF
[Unit]
Description=suricata daemon
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/var/run/
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid --af-packet -D -vvv
Type=forking

[Install]
WantedBy=multi-user.target
EOF
check_service suricata

echo "Provisioning Suricata rules"
pip install suricata-update
suricata-update update-sources

for src in et/open ptresearch/attackdetection oisf/trafficid; do suricata-update list-enabled-sources | grep $src || suricata-update enable-source $src >> /vagrant/provision.log 2>&1 ; done
suricata-update >> /vagrant/provision.log 2>&1
echo "Reloading Suricata rules"
suricatasc -c "reload-rules"

echo "Provisioning InfluxDB"
cd $PKGDIR
[[ -f $INFLUX ]] || wget $WGET_PARAMS https://dl.influxdata.com/influxdb/releases/$INFLUX -O $INFLUX
dpkg -s influxdb || dpkg -i $INFLUX > /dev/null 2>&1
systemctl stop influxdb.service
check_service influxdb

echo "Provisioning Grafana"
cd $PKGDIR
[[ -f $GRAFANA ]] || wget $WGET_PARAMS https://s3-us-west-2.amazonaws.com/grafana-releases/release/$GRAFANA -O $GRAFANA
apt-get -y install libfontconfig > /dev/null 2>&1
dpkg -s grafana || dpkg -i $GRAFANA > /dev/null 2>&1
systemctl stop grafana-server.service
check_service grafana-server

sleep 1
curl -s -XPOST --user admin:admin $EXPOSE:3000/api/datasources -H "Content-Type: application/json" -d '{
  "name": "telegraf",
  "type": "influxdb",
  "access": "proxy",
  "url": "http://localhost:8086",
  "database": "telegraf",
  "isDefault": true
}'

echo "Provisioning Telegraf"
cd $PKGDIR
[[ -f $TELEGRAF ]] || wget $WGET_PARAMS https://dl.influxdata.com/telegraf/releases/$TELEGRAF -O $TELEGRAF
dpkg -i $TELEGRAF > /dev/null 2>&1

systemctl stop telegraf.service
FILE=/etc/telegraf/telegraf.conf
grep "CDMCS" $FILE || cat > $FILE <<EOF
[global_tags]
  year = "2018"

[agent]
  hostname = "CDMCS"
  omit_hostname = false
  interval = "1s"
  round_interval = true
  metric_buffer_limit = 1000
  flush_buffer_when_full = true
  collection_jitter = "0s"
  flush_interval = "60s"
  flush_jitter = "10s"
  debug = false
  quiet = true

[[outputs.influxdb]]
  database  = "telegraf"
  urls  = ["http://localhost:8086"]

[[inputs.cpu]]
  percpu = true
  totalcpu = true
[[inputs.disk]]
  ignore_fs = ["tmpfs", "devtmpfs"]
[[inputs.diskio]]
[[inputs.kernel]]
[[inputs.mem]]
[[inputs.net]]
[[inputs.netstat]]
[[inputs.processes]]
[[inputs.swap]]
[[inputs.system]]
EOF

check_service telegraf

chmod u+x /vagrant/genTraffic.sh
/vagrant/genTraffic.sh

echo "DONE :: start $start end $(date)"
