#!/bin/bash

check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive|failed" && systemctl start $1.service
  systemctl status $1.service
}

# params
DOCKERIZE=true
DEBUG=true
EXPOSE=192.168.10.11
PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"

PATH=$PATH:/data/moloch/bin

grep PATH /home/vagrant/.bashrc || echo "export PATH=$PATH" >> /home/vagrant/.bashrc
grep PATH /root/.bashrc || echo "export PATH=$PATH" >> /root/.bashrc

# versions
ELA="elasticsearch-oss-6.6.2.deb"
KIBANA="kibana-oss-6.6.2-amd64.deb"
INFLUX="influxdb_1.7.3_amd64.deb"
TELEGRAF="telegraf_1.9.4-1_amd64.deb"
GRAFANA="grafana_5.4.3_amd64.deb"
EVEBOX="evebox_0.10.2_amd64.deb"

DOCKER_ELA="docker.elastic.co/elasticsearch/elasticsearch-oss:6.6.2"
DOCKER_KIBANA="docker.elastic.co/kibana/kibana-oss:6.6.2"
DOCKER_EVEBOX="jasonish/evebox"
DOCKER_INFLUXDB="influxdb"
DOCKER_GRAFANA="grafana/grafana"

MOLOCH="moloch_1.7.1-1_amd64.deb"
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
grep "vm.max_map_count" $FILE || cat >> $FILE <<EOF
vm.max_map_count=262144
EOF
sysctl -p

echo $start >  /vagrant/provision.log
echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4
export DEBIAN_FRONTEND=noninteractive

echo "Configuring DOCKER"
docker network ls | grep cdmcs >/dev/null || docker network create -d bridge cdmcs

echo "Provisioning REDIS"
docker ps -a | grep redis || docker run -dit --name redis -h redis --network cdmcs --restart unless-stopped -p 6379:6379 --log-driver syslog --log-opt tag="redis" redis

echo "Installing prerequisite packages..."
apt-get update && apt-get -y install jq wget curl python-minimal python-pip python3-pip python-yaml libpcre3-dev libyaml-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev libsnappy-dev >> /vagrant/provision.log 2>&1

echo "Provisioning JAVA"
if [ $DOCKERIZE = false ]; then
  java -version || apt-get install -y openjdk-8-jre-headless >> /vagrant/provision.log 2>&1
fi

# elastic
echo "Provisioning ELASTICSEARCH"
if [ $DOCKERIZE = true ]; then
  docker ps -a | grep elastic || docker run -dit --name elastic -h elastic --network cdmcs -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" --restart unless-stopped -p 127.0.0.1:9200:9200 --log-driver syslog --log-opt tag="elastic" $DOCKER_ELA 
else
  cd $PKGDIR
  [[ -f $ELA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/elasticsearch/$ELA -O $ELA
  dpkg -s elasticsearch || dpkg -i $ELA > /dev/null 2>&1

  sed -i 's/-Xms1g/-Xms512m/g' /etc/elasticsearch/jvm.options
  sed -i 's/-Xmx1g/-Xmx512m/g' /etc/elasticsearch/jvm.options
  check_service elasticsearch
fi

sleep 3

# kibana
echo "Provisioning KIBANA"
if [ $DOCKERIZE = true ]; then
  docker ps -a | grep kibana || docker run -dit --name kibana -h kibana --network cdmcs  -e "SERVER_NAME=kibana" -e "ELASTICSEARCH_URL=http://elastic:9200" --restart unless-stopped -p 5601:5601 --log-driver syslog --log-opt tag="kibana" $DOCKER_KIBANA
else
  cd $PKGDIR
  [[ -f $KIBANA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/kibana/$KIBANA -O $KIBANA
  dpkg -s kibana || dpkg -i $KIBANA > /vagrant/provision.log 2>&1

  FILE=/etc/kibana/kibana.yml
  grep "provisioned" $FILE || cat >> $FILE <<EOF
# provisioned
server.host: "0.0.0.0"
EOF
  check_service kibana
fi

echo "Configuring interfaces"
for iface in ${ifaces//;/ }; do
  echo "Setting capture params for $iface"
  for i in rx tx tso gso gro tx nocache copy sg rxvlan; do ethtool -K $iface $i off > /dev/null 2>&1; done
done

# suricata
install_suricata_from_ppa(){
  add-apt-repository ppa:oisf/suricata-stable > /dev/null 2>&1 \
  && apt-get update > /dev/null \
  && apt-get install -y suricata > /dev/null
}
echo "Provisioning SURICATA"
suricata -V || install_suricata_from_ppa
pip3 install --upgrade suricata-update

touch  /etc/suricata/threshold.config
mkdir -p /var/lib/suricata/rules
[[ -f /var/lib/suricata/rules/scirius.rules ]] || touch /etc/suricata/rules/scirius.rules
[[ -f /var/lib/suricata/rules/suricata.rules ]] || touch /etc/suricata/rules/suricata.rules

FILE=/var/lib/suricata/rules/custom.rules
[[ -f $FILE ]] || cat > $FILE <<EOF
alert http \$HOME_NET any -> \$EXTERNAL_NET any (msg:"CDMCS: External Windows executable download"; flow:established,to_server; content:"GET "; uricontent:".exe"; nocase; classtype:policy-violation; sid:3000001; rev:1; metadata:created_at 2018_01_19, updated_at 2018_01_19;) 
alert dns any any -> any any (msg:"CDMCS: DNS request for Facebook"; content:"facebook"; classtype:policy-violation; sid:3000002; rev:1; metadata:created_at 2018_01_19, updated_at 2018_01_19;)
alert tls any any -> any any (msg:"CDMCS: Facebook certificate detected"; tls.subject:"facebook"; classtype:policy-violation; sid:3000003; rev:1; metadata:created_at 2018_01_19, updated_at 2018_01_19;)
EOF

FILE=/var/lib/suricata/rules/lua.rules
[[ -f $FILE ]] || cat > $FILE <<EOF
alert tls any any -> any any (msg:"CDMCS TLS Self Signed Certificate"; flow:established; luajit:self-signed-cert.lua; tls.store; classtype:protocol-command-decode; sid:3000004; rev:1;)
EOF

FILE=/var/lib/suricata/rules/self-signed-cert.lua
[[ -f $FILE ]] || cat > $FILE <<EOF
function init (args)
    local needs = {}
    needs["tls"] = tostring(true)
    return needs
end
function match(args)
    version, subject, issuer, fingerprint = TlsGetCertInfo();
    if subject == issuer then
        return 1
    else
        return 0
    end
end
EOF

mkdir -p /var/lib/suricata/scripts
FILE=/var/lib/suricata/scripts/new-observed-tls.lua
[[ -f $FILE ]] || cat > $FILE <<EOF
function init (args)
    local needs = {}
    needs["protocol"] = "tls"
    return needs
end
function setup (args)
    name = "tls.log"
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    seen = {}
end
function log(args)
    version, subject, issuer, fingerprint = TlsGetCertInfo()
    serial = TlsGetCertSerial()
    if version == nil then
        version = "<nil>"
    end
    if subject == nil then
        subject = "<nil>"
    end
    if issuer == nil then
        issuer = "<nil>"
    end
    if fingerprint == nil then
        fingerprint = "<nil>"
    end
    if fingerprint ~= nil then
        if seen[fingerprint] == nil then
            file:write(version .. "|" .. subject .. "|" .. issuer .. "|" .. fingerprint .. "|" .. serial .. "\n");
            file:flush();
            seen[fingerprint] = true
        end
    end
end
function deinit (args)
    file:close(file)
end
EOF

if $DEBUG ; then ip addr show; fi
systemctl stop suricata
pgrep Suricata || [[ -f /var/run/suricata.pid ]] && rm /var/run/suricata.pid

echo "Configuring SURICATA"

echo "Adding includes for SURICATA"
FILE=/etc/suricata/suricata.yaml
grep "cdmcs" $FILE || cat >> $FILE <<EOF
include: /etc/suricata/cdmcs-detect.yaml
include: /etc/suricata/cdmcs-logging.yaml
EOF

echo "Adding detects for SURICATA"
FILE=/etc/suricata/cdmcs-detect.yaml
grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
af-packet:
  - interface: enp0s3
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: enp0s8
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: /var/lib/suricata/rules
rule-files:
 -  suricata.rules
 -  custom.rules
 -  lua.rules
sensor-name: CDMCS
EOF

echo "Adding outputs for SURICATA"
FILE=/etc/suricata/cdmcs-logging.yaml

grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
outputs:
  - fast:
      enabled: no
      filename: fast.log
      append: yes
  - tls-store:
      enabled: yes
  - lua:
      enabled: yes
      scripts-dir: /var/lib/suricata/scripts/
      scripts:
        - new-observed-tls.lua
  - eve-log:
      enabled: 'yes'
      filetype: regular #regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json
      types:
        - alert:
            payload: no             # enable dumping payload in Base64
            payload-buffer-size: 4kb # max size of payload buffer to output in eve-log
            payload-printable: no   # enable dumping payload in printable (lossy) format
            packet: yes              # enable dumping of packet (without stream segments)
            http-body: no           # enable dumping of http body in Base64
            http-body-printable: no # enable dumping of http body in printable format
            metadata: no             # enable inclusion of app layer metadata with alert. Default yes
            tagged-packets: no
EOF

#if $DEBUG ; then suricata -T -vvv; fi
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
check_service suricata || exit 1

echo "Updating rules"
suricata-update enable-source ptresearch/attackdetection
suricata-update enable-source sslbl/ssl-fp-blacklist
suricata-update enable-source oisf/trafficid
suricata-update enable-source tgreen/hunting
suricata-update list-enabled-sources
suricata-update
sleep 3
suricatasc -c "reload-rules" || exit 1

echo "Provision moloch"
#cp /vagrant/buildMoloch.sh /home/$USER/buildMoloch.sh && chown $USER /home/$USER/buildMoloch.sh
#[[ -f /home/$USER/moloch-$MOLOCH/bin/moloch-capture ]] || time su -c "bash /home/$USER/buildMoloch.sh $MOLOCH" $USER
cd $PKGDIR
[[ -f $MOLOCH ]] || wget $WGET_PARAMS https://files.molo.ch/builds/ubuntu-18.04/$MOLOCH
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

echo "Configuring capture plugins"
sed -i -e 's,#wiseHost=127.0.0.1,wiseHost=127.0.0.1\nplugins=wise.so;suricata.so\nsuricataAlertFile=/var/log/suricata/eve.json\nviewerPlugins=wise.js\nwiseTcpTupleLookups=true\nwiseUdpTupleLookups=true\n,g' config.ini

echo "Configuring wise"
TAGGER_FILE="/data/moloch/etc/tagger.txt"
[[ -f $TAGGER_FILE ]] || cat > $TAGGER_FILE <<EOF
#field:cdmcs.name;kind:lotermfield;count:true;friendly:Name;db:cdmcs.name;help:Traffic owner;shortcut:0
#field:cdmcs.type;kind:lotermfield;count:true;friendly:Type;db:cdmcs.type;help:Traffic type;shortcut:1
192.168.10.11;0=local
10.0.2.15;0=local
8.8.8.8;0=google;1=dns
8.8.4.4;0=google;1=dns
1.1.1.1;0=cloudflare;1=dns
66.6.32.31;0=tumblr;1=web
66.6.33.31;0=tumblr;1=web
66.6.33.159;0=tumblr;1=web
EOF

cp wise.ini.sample wiseService.ini
grep CDMCS wiseService.ini || cat >> wiseService.ini <<EOF
# CDMCS
[reversedns]
ips=10.0.0.0/8
field=asset

[cache]
type=redis
url=redis://127.0.0.1:6379/1

[file:ip]
file=$TAGGER_FILE
tags=ipwise
type=ip
format=tagger
EOF

echo "Configuring databases"
cd /data/moloch/db
if [[ `./db.pl localhost:9200 info | grep "DB Version" | cut -d ":" -f2 | tr -d " "` -eq -1 ]]; then
  echo "INIT" | ./db.pl localhost:9200 init
fi

cd /data/moloch/bin
./moloch_update_geo.sh > /dev/null 2>&1
chown nobody:daemon /data/moloch/raw

echo "Configuring system limits"
ulimit -l unlimited
grep memlocl /etc/security/limits.conf || echo "nofile 128000 - memlock unlimited" >> /etc/security/limits.conf
mkdir /data/moloch/raw && chown nobody:daemon /data/moloch/raw

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

# parliament
PARLIAMENTPASSWORD=admin
if curl ${EXPOSE}:8005/eshealth.json > /dev/null 2>&1 ; then
   if curl ${EXPOSE}:8008 > /dev/null 2>&1; then
     echo "parliament: already in use ${EXPOSE}:8008"
   else
      echo "parliament: preparing ..."  
      cd /data/moloch/parliament
      [ -f parliament.json ] && mv parliament.json parliament.json.$(date +%s)
      /data/moloch/bin/node parliament.js > >(logger -p daemon.info -t capture) 2> >(logger -p daemon.err -t capture) & sleep 1 ; echo $! > /var/run/parliament.pid  

      token=$(curl -s -XPUT  ${EXPOSE}:8008/parliament/api/auth/update -d newPassword=${PARLIAMENTPASSWORD} | jq .token | sed 's/"//g')
      H="Content-Type: application/json;charset=UTF-8"
      GROUP='group1'
      id=$(curl -s -XPOST -H "${H}" ${EXPOSE}:8008/parliament/api/groups --data "{\"token\":\"${token}\", \"title\":\"${GROUP}\"}"| jq .group.id)
      CLUSTER='cluster1'
      URL="http://${EXPOSE}:8005"
      curl -s -XPOST -H "${H}" ${EXPOSE}:8008/parliament/api/groups/${id}/clusters --data "{\"token\":\"${token}\", \"title\":\"${CLUSTER}\",\"url\":\"${URL}\"}"
   fi
else  
  echo "parliament: can not get eshealth from ${EXPOSE}:8005"
fi

# influx
echo "Provisioning INFLUXDB"
if [ $DOCKERIZE = true ]; then
  docker ps -a | grep influx || docker run -dit --name influx -h influx --network cdmcs --restart unless-stopped -p 8086:8086 --log-driver syslog --log-opt tag="influx" $DOCKER_INFLUXDB
else
  cd $PKGDIR
  [[ -f $INFLUX ]] || wget $WGET_PARAMS https://dl.influxdata.com/influxdb/releases/$INFLUX -O $INFLUX
  dpkg -s influxdb || dpkg -i $INFLUX > /dev/null 2>&1
  systemctl stop influxdb.service
  check_service influxdb
fi

# grafana
echo "Provisioning GRAFANA"
mkdir -p /etc/grafana/provisioning/dashboards/

FILE=/etc/grafana/provisioning/dashboards/cdmcs.yml
[[ -f $FILE ]] || cat > $FILE <<EOF
apiVersion: 1

providers:
- name: 'cdmcs'
  orgId: 1
  folder: ''
  type: file
  disableDeletion: false
  updateIntervalSeconds: 10
  options:
    path: /vagrant/grafana-provision/
EOF

if [ $DOCKERIZE = true ]; then
  docker ps -a | grep grafana || docker run -dit --name grafana -h grafana --network cdmcs --restart unless-stopped -p 3000:3000 -v /etc/grafana/provisioning:/etc/grafana/provisioning -v /vagrant:/vagrant --log-driver syslog --log-opt tag="grafana" $DOCKER_GRAFANA
else
  cd $PKGDIR
  [[ -f $GRAFANA ]] || wget $WGET_PARAMS https://s3-us-west-2.amazonaws.com/grafana-releases/release/$GRAFANA -O $GRAFANA
  apt-get -y install libfontconfig > /dev/null 2>&1
  dpkg -s grafana || dpkg -i $GRAFANA > /dev/null 2>&1

  sed -i 's/;provisioning = conf\/provisioning/provisioning = \/etc/\/grafana\/provisioning/g' /etc/grafana/grafana.ini 
  systemctl stop grafana-server.service

  check_service grafana-server
fi

sleep 10
echo "configuring grafana data sources"
curl -s -XPOST --user admin:admin $EXPOSE:3000/api/datasources -H "Content-Type: application/json" -d "{
    \"name\": \"telegraf\",
    \"type\": \"influxdb\",
    \"access\": \"proxy\",
    \"url\": \"http://$EXPOSE:8086\",
    \"database\": \"telegraf\",
    \"isDefault\": true
}"

# telegraf
echo "Provisioning TELEGRAF"
cd $PKGDIR
[[ -f $TELEGRAF ]] || wget $WGET_PARAMS https://dl.influxdata.com/telegraf/releases/$TELEGRAF -O $TELEGRAF
dpkg -i $TELEGRAF > /dev/null 2>&1

systemctl stop telegraf.service
FILE=/etc/telegraf/telegraf.conf
grep "CDMCS" $FILE || cat > $FILE <<EOF
[global_tags]
  year = "2019"
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
[[inputs.interrupts]]
EOF

FILE=/etc/telegraf/telegraf.d/elastic.conf
grep "CDMCS" $FILE || cat > $FILE <<EOF
[[inputs.elasticsearch]]
  servers = ["http://localhost:9200"]
  http_timeout = "5s"
  local = false
  cluster_health = true
  cluster_stats = true
  cluster_stats_only_from_master = false
EOF

FILE=/etc/telegraf/telegraf.d/ethtool.conf
grep "CDMCS" $FILE || cat > $FILE <<EOF
[[inputs.exec]]
  commands = ["/home/vagrant/go/bin/ethflux enp"]
  timeout = "5s"
  data_format = "influx"
EOF

FILE=/etc/telegraf/telegraf.d/moloch.conf
grep "CDMCS" $FILE || cat > $FILE <<EOF
[[inputs.procstat]]
  pid_finder = "pgrep"
  exe = "moloch-capture"
EOF

if [ $DOCKERIZE = true ]; then
  FILE=/etc/telegraf/telegraf.d/elastic.conf
  grep "CDMCS" $FILE || cat > $FILE <<EOF
[[inputs.docker]]
  endpoint = "unix:///var/run/docker.sock"
  gather_services = false
  container_names = []
  container_name_include = []
  container_name_exclude = []
  timeout = "5s"
  perdevice = true
  total = false
  docker_label_include = []
  docker_label_exclude = []
  tag_env = ["JAVA_HOME", "HEAP_SIZE"]
EOF

  # massive privilege escalation issue
  echo "Adding telegraf user to Docker group. Massive privilege escalation. Do not do at home!"
  adduser telegraf docker
fi

check_service telegraf

echo "making some noise"
while : ; do curl -s https://www.facebook.com/ > /dev/null 2>&1 ; sleep 1 ; done &
while : ; do curl -s https://sysadminnid.tumblr.com/ > /dev/null 2>&1 ; sleep 30 ; done &
while : ; do curl -s http://testmyids.com > /dev/null 2>&1 ; sleep 30 ; done &
while : ; do curl -s -k https://self-signed.badssl.com/ > /dev/null 2>&1 ; sleep 5 ; done &
while : ; do dig NS berylia.org @1.1.1.1 > /dev/null 2>&1 ; sleep 22 ; done &
while : ; do dig NS berylia.org @8.8.8.8 > /dev/null 2>&1 ; sleep 38 ; done &

echo "DONE :: start $start end $(date)"
