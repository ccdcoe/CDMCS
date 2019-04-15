check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive|failed" && systemctl start $1.service
  systemctl status $1.service
}

# params
DOCKERIZE=false
DEBUG=true
EXPOSE=192.168.10.11
PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"

HOME=/home/vagrant
GOPATH=$HOME/go/
GOROOT=$HOME/.local/go
PATH=$PATH:/data/moloch/bin:$GOROOT/bin:$GOPATH/bin:$HOME/.local/go

grep PATH $HOME/.bashrc || echo "export PATH=$PATH" >> $HOME/.bashrc
grep PATH /root/.bashrc || echo "export PATH=$PATH" >> /root/.bashrc

# versions
ELA="elasticsearch-oss-6.7.0.deb"
KIBANA="kibana-oss-6.7.0-amd64.deb"
INFLUX="influxdb_1.7.5_amd64.deb"
GRAFANA="grafana_6.1.0_amd64.deb"

TELEGRAF="telegraf_1.10.2-1_amd64.deb"
GOLANG="go1.12.1.linux-amd64.tar.gz"

DOCKER_ELA="docker.elastic.co/elasticsearch/elasticsearch-oss:6.7.0"
DOCKER_KIBANA="docker.elastic.co/kibana/kibana-oss:6.7.0"
DOCKER_INFLUXDB="influxdb:alpine"
DOCKER_GRAFANA="grafana/grafana:latest"

MOLOCH="moloch_1.8.0-1_amd64.deb"
USER="vagrant"

if [[ -n $(ip link show | grep eth0) ]]; then
  IFACE_EXT="eth0"
  IFACE_INT="eth1"
else
  IFACE_EXT="enp0s3"
  IFACE_INT="enp0s8"
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

echo "Configuring DOCKER"
docker network ls | grep cdmcs >/dev/null || docker network create -d bridge cdmcs

echo "Provisioning REDIS"
docker ps -a | grep redis || docker run -dit --name redis -h redis --network cdmcs --restart unless-stopped -p 6379:6379 --log-driver syslog --log-opt tag="redis" redis

echo "Installing prerequisite packages..."
apt-get update && apt-get -y install jq wget curl pcregrep python-minimal python-pip python3-pip python-yaml libpcre3-dev libyaml-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev libsnappy-dev numactl >> /vagrant/provision.log 2>&1

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
  - interface: $IFACE_EXT
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: $IFACE_INT
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
cd $PKGDIR
[[ -f $MOLOCH ]] || wget $WGET_PARAMS https://files.molo.ch/builds/ubuntu-18.04/$MOLOCH
dpkg -s moloch || dpkg -i $MOLOCH

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

echo "Configuring capture plugins"
sed -i -e 's,#wiseHost=127.0.0.1,wiseHost=127.0.0.1\nwiseCacheSecs=60\nplugins=wise.so;suricata.so\nsuricataAlertFile=/var/log/suricata/eve.json\nviewerPlugins=wise.js\nwiseTcpTupleLookups=true\nwiseUdpTupleLookups=true\n,g' config.ini

echo "Configuring custom views and fields"
grep "custom-fields" $FILE || cat >> $FILE <<EOF
[custom-fields]
cdmcs.name=kind:lotermfield;count:true;friendly:Name;db:cdmcs.name;help:Traffic owner
cdmcs.type=kind:lotermfield;count:true;friendly:Type;db:cdmcs.type;help:Traffic type
EOF

grep "custom-views" $FILE || cat >> $FILE <<EOF
[custom-views]
ls19=title:Locked Shields 2019;require:ls19;fields:ls19.target,ls19.name,ls19.short,ls19.zone,ls19.team,ls19.ws_template,ls19.ws_iter,ls19.ws_family,ls19.ws_release,ls19.ws_arch
cdmcs=title:Cyber Defence Monitoring Course;require:cdmcs;fields:cdmcs.name,cdmcs.type
EOF

grep "wise-types" $FILE || cat >> $FILE <<EOF
[wise-types]
mac=db:srcMac;db:dstMac
EOF

echo "Configuring wise"
TAGGER_FILE="/data/moloch/etc/tagger.txt"
[[ -f $TAGGER_FILE ]] || cat > $TAGGER_FILE <<EOF
#field:cdmcs.name;shortcut:0
#field:cdmcs.type;shortcut:1
192.168.10.11;0=local
10.0.2.15;0=local
8.8.8.8;0=google;1=dns
8.8.4.4;0=google;1=dns
1.1.1.1;0=cloudflare;1=dns
66.6.32.31;0=tumblr;1=web
66.6.33.31;0=tumblr;1=web
66.6.33.159;0=tumblr;1=web
EOF

for addr in $(dig A sysadminnid.tumblr.com | grep IN | grep -v \; | pcregrep -o1 'tumblr\.com\.\s+\d+\s+\w+\s+A\s+(\S+)'); do
  docker exec redis redis-cli set $addr "$addr;cdmcs.name=tumblr;cdmcs.type=web"
done

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

[redis:ip]
url=redis://127.0.0.1:6379/0
tags=redis
type=ip
format=tagger
EOF

grep bloom wiseService.ini || cat >> wiseService.ini <<EOF
[bloom]
bits=300000
functions=16
tag=bloom
EOF

cd /data/moloch/wiseService

PATH=$PATH npm install bloomfilter
PATH=$PATH npm install hashtable

FILE="/data/moloch/wiseService/source.bloom.js"
grep CDMCS $FILE || cat >> $FILE <<EOF
/* [bloom]
 * bits=200000
 * functions=16
 * tag=newdns
 */

'use strict';

var wiseSource     = require('./wiseSource.js')
  , util           = require('util')
  , bloom          = require('bloomfilter')
  ;

//////////////////////////////////////////////////////////////////////////////////
function BloomSource (api, section) {
  BloomSource.super_.call(this, api, section);

  this.bits = api.getConfig(section, "bits");
  this.fn = api.getConfig(section, "functions");
  this.tagval = api.getConfig(section, "tag");

  // Check if variables needed are set, if not return
  if (this.bits === undefined) {
    return console.log(this.section, "- Bloom filter bits undefined");
  }
  if (this.fn === undefined) {
    return console.log(this.section, "- Bloom filter hash functions undefined");
  }
  if (this.tag === undefined) {
    this.tab == "bloom";
  }

  this.dns = new bloom.BloomFilter(
    this.bits, // number of bits to allocate.
    this.fn    // number of hash functions.
  );

  this.tagsField = this.api.addField("field:tags");

  // Memory data sources will have this section to load their data
  this.cacheTimeout = -1;
  //setImmediate(this.load.bind(this));
  //setInterval(this.load.bind(this), 5*60*1000);

  // Add the source as available
  this.api.addSource("bloom", this);
}
util.inherits(BloomSource, wiseSource);
//////////////////////////////////////////////////////////////////////////////////
BloomSource.prototype.getDomain = function(domain, cb) {
  if (!this.dns.test(domain)) {
    this.dns.add(domain);
    return cb(null, {num: 1, buffer: wiseSource.encode(this.tagsField, this.tagval)});
  }
  return cb(null, wiseSource.emptyResult);
};
//////////////////////////////////////////////////////////////////////////////////
exports.initSource = function(api) {
  var source = new BloomSource(api, "bloom");
};
EOF

wget $WGET_PARAMS https://raw.githubusercontent.com/markuskont/moloch/master/wiseService/source.ls19.js -O /data/moloch/wiseService/source.ls19.js

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
grep memlock /etc/security/limits.conf || echo "nofile 128000 - memlock unlimited" >> /etc/security/limits.conf
mkdir /data/moloch/raw && chown nobody:daemon /data/moloch/raw

echo "Configuring systemd services"

FILE=/etc/systemd/system/moloch-wise.service
grep "moloch-wise" $FILE || cat > $FILE <<EOF
[Unit]
Description=Moloch WISE
After=network.target

[Service]
Type=simple
Restart=on-failure
ExecStart=/data/moloch/bin/node wiseService.js -c /data/moloch/etc/wiseService.ini
WorkingDirectory=/data/moloch/wiseService
SyslogIdentifier=moloch-wise

[Install]
WantedBy=multi-user.target
EOF

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
for service in wise viewer capture ; do
  systemctl enable moloch-$service.service
  systemctl start moloch-$service.service
  systemctl status moloch-$service.service
done

pgrep moloch-capture || exit 1

mkdir -p /home/vagrant/.local/bin && chown -R vagrant /home/vagrant/.local
su - vagrant -c "pip3 install --user --upgrade psutil"

FILE=/home/vagrant/.local/bin/set-capture-affinit.py
grep "get_numa_cores" $FILE || cat > $FILE <<EOF
#!/usr/bin/env python3

import psutil
import subprocess
import re
import sys
import os.path

def get_moloch_capture_parent():
    procs = {p.pid: p.info for p in psutil.process_iter(attrs=['pid', 'name', 'username'])}
    parent = {k: v for k, v in procs.items() if "moloch-capture" in v["name"]}
    parent = list(parent.values())[0]["pid"]
    parent = psutil.Process(pid=parent)
    return parent

def get_moloch_workers(parent):
    workers = parent.threads()
    workers = [w.id for w in workers]
    workers = [psutil.Process(pid=p) for p in workers]
    workers = [{"pid": p.pid, "name": p.name()} for p in workers]
    return workers

def get_numa_cores(node):
    numa = subprocess.run(['numactl', '--hardware'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    numa = numa.split("\n")
    numa = [v.split(":")[1].strip() for v in numa if "node {} cpus:".format(NODE) in v][0]
    numa = numa.split()
    numa = [int(v) for v in numa]
    return numa

NODE=0
CAP_IFACE="$IFACE_EXT"

if __name__ == "__main__":

    numa = get_numa_cores(NODE)

    intr_thread = numa[0]
    cap_thread = numa[1]
    worker_threads = numa[2:]

    cap_pattern = re.compile("^moloch-(?:capture|simple|af\d+-\d+)$")
    pkt_pattern = re.compile("^moloch-pkt\d+$")

    parent = get_moloch_capture_parent()
    workers = get_moloch_workers(parent)

    cap_threads = [t for t in workers if cap_pattern.match(t["name"])]
    pkt_threads = [t for t in workers if pkt_pattern.match(t["name"])]

    if len(pkt_threads) > len(worker_threads):
        print("Too many moloch workers for {} cpu threads".format(len(worker_threads)))
        sys.exit(1)

    for thread in cap_threads:
        subprocess.call(['/usr/bin/sudo', 'taskset', '-pc', str(cap_thread), str(thread["pid"])])

    for i, thread in enumerate(pkt_threads):
        subprocess.call(['/usr/bin/sudo', 'taskset', '-pc', str(worker_threads[i]), str(thread["pid"])])

    lines = []
    with open("/proc/interrupts", "rb") as f:
        lines = [l.decode().split(":")[0].lstrip() for l in f if CAP_IFACE in l.decode()]

    if len(lines) == 0 or len(lines) > 1:
        print("found {} irq for {}, should be 1".format(len(lines), CAP_IFACE))
        sys.exit(1)

    irq = lines[0]
    irq = os.path.join('/proc/irq', str(irq), 'smp_affinity_list')

    subprocess.Popen(['/usr/bin/sudo /bin/bash -c \'echo {} > {}\''.format(intr_thread, irq)], shell=True)
EOF
chown vagrant $FILE
chmod u+x $FILE
su - vagrant -c "python3 $FILE"

echo "Adding viewer user"
cd /data/moloch/viewer && ../bin/node addUser.js vagrant vagrant vagrant --admin

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

# golang
echo "Provisioning GOLANG"
source ~/.bashrc

mkdir -p $GOPATH/{bin,src,pkg} && chown -R vagrant $GOPATH
mkdir -p $GOROOT && chown -R vagrant $GOROOT
cd $PKGDIR
[[ -f $GOLANG ]] || wget $WGET_PARAMS https://dl.google.com/go/$GOLANG -O $GOLANG
tar -xzf $GOLANG -C /home/vagrant/.local
su - vagrant -c "PATH=$PATH go env"
su - vagrant -c "PATH=$PATH go get -u github.com/DCSO/ethflux"
su - vagrant -c "PATH=$PATH go install github.com/DCSO/ethflux"

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
  commands = ["$GOPATH/bin/ethflux enp"]
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
  FILE=/etc/telegraf/telegraf.d/docker.conf
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
while : ; do curl -s https://www.facebook.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s https://sysadminnid.tumblr.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s http://testmyids.com > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s -k https://self-signed.badssl.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do dig NS berylia.org @1.1.1.1 > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do dig NS berylia.org @8.8.8.8 > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &

echo "DONE :: start $start end $(date)"

echo "Sleeping 120 seconds for data to ingest."; sleep 120
curl -ss -u vagrant:vagrant --digest "http://$EXPOSE:8005/sessions.csv?counts=0&date=1&fields=ipProtocol,totDataBytes,srcDataBytes,dstDataBytes,firstPacket,lastPacket,srcIp,srcPort,dstIp,dstPort,totPackets,srcPackets,dstPackets,totBytes,srcBytes,suricata.signature&length=1000&expression=suricata.signature%20%3D%3D%20EXISTS%21"
curl -ss -u vagrant:vagrant --digest "http://$EXPOSE:8005/unique.txt?exp=host.dns&counts=0&date=1&expression=tags%20%3D%3D%20bloom"
