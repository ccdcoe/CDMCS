check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive|failed" && systemctl start $1.service
  systemctl status $1.service
}

# params
DEBUG=true
EXPOSE=127.0.0.1
PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"

HOME=/home/vagrant
GOPATH=$HOME/go/
GOROOT=$HOME/.local/go
PATH=$PATH:/data/moloch/bin:$GOROOT/bin:$GOPATH/bin:$HOME/.local/go

grep PATH $HOME/.bashrc || echo "export PATH=$PATH" >> $HOME/.bashrc
grep PATH /root/.bashrc || echo "export PATH=$PATH" >> /root/.bashrc

USER="vagrant"

# versions
ELASTIC_VERSION="7.6.0"
INFLUX_VERSION="1.7.9"
GRAFANA_VERSION="6.6.0"
TELEGRAF_VERSION="1.13.2"
GOLANG_VERSION="1.13.6"
MOLOCH_VERSION="2.2.1"

ELA="elasticsearch-oss-${ELASTIC_VERSION}-amd64.deb"
KIBANA="kibana-oss-${ELASTIC_VERSION}-amd64.deb"
INFLUX="influxdb_${INFLUX_VERSION}_amd64.deb"
GRAFANA="grafana_${GRAFANA_VERSION}_amd64.deb"

TELEGRAF="telegraf_${TELEGRAF_VERSION}-1_amd64.deb"
GOLANG="go${GOLANG_VERSION}.linux-amd64.tar.gz"

DOCKER_ELA="docker.elastic.co/elasticsearch/elasticsearch-oss:${ELASTIC_VERSION}"
DOCKER_KIBANA="docker.elastic.co/kibana/kibana-oss:${ELASTIC_VERSION}"
DOCKER_LOGSTASH="docker.elastic.co/logstash/logstash-oss:${ELASTIC_VERSION}"

DOCKER_INFLUXDB="influxdb:${INFLUX_VERSION}-alpine"
DOCKER_GRAFANA="grafana/grafana:${GRAFANA_VERSION}"

MOLOCH="moloch_${MOLOCH_VERSION}-1_amd64.deb"

ELASTSIC_MEM=512
LOGSTASH_MEM=512

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

echo "Configuring DOCKER"
docker network ls | grep cdmcs >/dev/null || docker network create -d bridge cdmcs

echo "Provisioning REDIS"
docker ps -a | grep redis || docker run -dit \
  --name redis \
  -h redis \
  --network cdmcs \
  --restart unless-stopped \
  -p 6379:6379 \
  --log-driver syslog --log-opt tag="redis" \
    redis

echo "Installing prerequisite packages..."
apt-get update && apt-get -y install jq wget curl pcregrep python-minimal python-pip python3-pip python-yaml libpcre3-dev libyaml-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev libsnappy-dev numactl >> /vagrant/provision.log 2>&1

# elastic
echo "Provisioning ELASTICSEARCH"
docker ps -a | grep elastic || docker run -dit \
  --name elastic \
  -h elastic \
  --network cdmcs \
  -e "ES_JAVA_OPTS=-Xms${ELASTSIC_MEM}m -Xmx${ELASTSIC_MEM}m" \
  -e "discovery.type=single-node" \
  --restart unless-stopped \
  -p 9200:9200 \
    $DOCKER_ELA 

# kibana
echo "Provisioning KIBANA"
docker ps -a | grep kibana || docker run -dit \
  --name kibana \
  -h kibana \
  --network cdmcs  \
  -e "SERVER_NAME=kibana" \
  -e "ELASTICSEARCH_HOSTS=http://elastic:9200" \
  --restart unless-stopped \
  -p 5601:5601 \
    $DOCKER_KIBANA

echo "Provisioning ELASTIC TEMPLATES"
curl -s -XPUT localhost:9200/_template/default   -H'Content-Type: application/json' -d '
{
 "order" : 0,
 "version" : 0,
 "index_patterns" : "suricata-*",
 "settings" : {
   "index" : {
     "refresh_interval" : "10s",
     "number_of_shards" : 3,
     "number_of_replicas" : 0
   }
 }, "mappings" : {
    "dynamic_templates" : [ {
      "message_field" : {
        "path_match" : "message",
        "match_mapping_type" : "string",
        "mapping" : {
          "type" : "text",
          "norms" : false
        }
      }
    }, {
      "string_fields" : {
        "match" : "*",
        "match_mapping_type" : "string",
        "mapping" : {
          "type" : "text", "norms" : false,
          "fields" : {
            "keyword" : { "type": "keyword", "ignore_above": 256 }
          }
        }
      }
    } ],
    "properties" : {
      "@timestamp": { "type": "date"},
      "@version": { "type": "keyword"},
      "geoip"  : {
        "dynamic": true,
        "properties" : {
          "ip": { "type": "ip" },
          "location" : { "type" : "geo_point" },
          "latitude" : { "type" : "half_float" },
          "longitude" : { "type" : "half_float" }
        }
      }
    }
  }
}
' || exit 1

curl -s -XPUT localhost:9200/_template/suricata   -H 'Content-Type: application/json' -d '
{
  "order": 10,
  "version": 0,
  "index_patterns": [
    "suricata-*",
    "logstash-*"
  ],
  "mappings":{
    "properties": {
      "src_ip": { 
        "type": "ip",
        "fields": {
          "keyword" : { "type": "keyword", "ignore_above": 256 }
        }
      },
      "dest_ip": { 
        "type": "ip",
        "fields": {
          "keyword" : { "type": "keyword", "ignore_above": 256 }
        }
      },
      "payload": { "type": "binary" }
    }
  }
}
' || exit 1

docker ps -a | grep evebox | docker run -tid --rm \
  --network cdmcs \
  -p 5636:5636 \
    jasonish/evebox:master  \
      -e http://elastic:9200 \
      --index suricata \
      --elasticsearch-keyword keyword \
      --host 0.0.0.0 \

echo "Provisioning RSYSLOG"
add-apt-repository ppa:adiscon/v8-stable
apt-get update
apt-get install rsyslog rsyslog-mmjsonparse rsyslog-elasticsearch -y
FILE=/etc/rsyslog.d/75-elastic.conf
grep "CDMCS" $FILE || cat >> $FILE <<'EOF'
# CDMCS
module(load="omelasticsearch")
module(load="mmjsonparse")
template(
  name="with-logstash-timestamp-format" 
  type="list") {
    constant(value="{\"@timestamp\":\"")                property(name="timegenerated" dateFormat="rfc3339")
    constant(value="\",")                               property(name="$!all-json"    position.from="3")
}
template(name="JSON" type="list") {
    property(name="$!all-json")
}
template(name="suricata-index" type="list") {
    constant(value="suricata-")
    property(name="timereported" dateFormat="rfc3339" position.from="1" position.to="4")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="6" position.to="7")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="9" position.to="10")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="12" position.to="13")
}
if $syslogtag contains 'suricata' and $msg startswith ' @cee:' then {
  action(type="mmjsonparse")
  if $parsesuccess == "OK" then action(
    type="omelasticsearch"
    template="with-logstash-timestamp-format"
    server="127.0.0.1"
    serverport="9200"
    searchIndex="suricata-index"
    dynSearchIndex="on"
    searchType="_doc"
  )
}
EOF

systemctl stop rsyslog.service
rsyslogd -N 1 || exit 1
check_service rsyslogd

# logstash
echo "Provisioning LOGSTASH"
grep redis /etc/hosts || echo "127.0.0.1 redis" >> /etc/hosts
grep elastic /etc/hosts || echo "127.0.0.1 elastic" >> /etc/hosts

mkdir -p /etc/logstash/conf.d/
FILE=/etc/logstash/conf.d/suricata.conf
grep "CDMCS" $FILE || cat > $FILE <<EOF
input {
  file {
    path => "/var/log/suricata/eve.json"
    tags => ["suricata", "CDMCS", "fromfile"]
  }
  redis {
    data_type => "list"
    host => "redis"
    port => 6379
    key  => "suricata"
    tags => ["suricata", "CDMCS", "fromredis"]
  }
}
filter {
  json { source => "message" }
  if 'syslog' not in [tags] {
    mutate { remove_field => [ "message", "Hostname" ] }
  }
}
output {
  elasticsearch {
    hosts => ["elastic"]
    index => "logstash-%{+YYYY.MM.dd.hh}"
    manage_template => false
    document_type => "_doc"
  }
}
EOF

# Not enough memory on small course vm
#docker ps -a | grep logstash || docker run -dit \
#  --name logstash \
#  -h logstash \
#  --network cdmcs \
#  -v /etc/logstash/conf.d/:/usr/share/logstash/pipeline/ \
#  -e "ES_JAVA_OPTS=-Xms${LOGSTASH_MEM}m -Xmx${LOGSTASH_MEM}m" \
#  --restart unless-stopped \
#    $DOCKER_LOGSTASH

FILE=/var/lib/suricata/scripts/alert2alerta.py
[[ -f $FILE ]] || cat > $FILE <<EOF
#!/usr/bin/env python3

import json
import requests
import sys

line = sys.stdin.readline()
data = json.loads(line)

assets = { "192.168.10.11": "singlehost" }

if data["src_ip"] in assets:
    resource = data["src_ip"]
elif data["dest_ip"] in assets:
    resource = data["dest_ip"]
else:
    resource = data["dest_ip"]

headers = { "Content-Type": "application/json" }
alert = {
        "environment": "Production",
        "event": data["alert"]["signature"],
        "resource": resource,
        "text": "Alert from {} to {} for {}".format(data["src_ip"], data["dest_ip"], data["alert"]["signature"]),
        "service": [resource],
        "severity": "major",
        "value": data["alert"]["severity"],
        "timeout": 60,
        }

url = "http://192.168.10.11:8080/api/alert"

resp = requests.post(url, data=json.dumps(alert), headers=headers)
print(resp.json())
EOF

sleep 5

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
alert http any any -> any any (msg:"CDMCS: Listed UA seen"; http.user_agent; to_sha256; dataset:isset,ua-seen; classtype:policy-violation; sid:3000004; rev:1; metadata:created_at 2020_01_29, updated_at 2020_01_29;)
alert dns any any -> any any (msg:"CDMCS: Listed DNS hash seen"; dns.query; to_sha256; dataset:isset,dns-sha256-seen; classtype:policy-violation; sid:3000005; rev:1; metadata:created_at 2020_01_29, updated_at 2020_01_29;)
alert http any any -> \$EXTERNAL_NET any (msg:"CDMCS: Bypass content delivery"; http.host; dataset:isset,http-content-delivery, type string, state /var/lib/suricata/content-deliver.lst; bypass; sid:3000006; rev:1; metadata:created_at 2020_02_28, updated_at 2020_02_28;)
alert http any any -> \$EXTERNAL_NET any (msg:"CDMCS: Collect unique user-agents"; http.user_agent; dataset:set,http-user-agents, type string, state /var/lib/suricata/http-user-agents.lst; bypass; sid:3000007; rev:1; metadata:created_at 2020_02_28, updated_at 2020_02_28;)
EOF

FILE=/var/lib/suricata/rules/lua.rules
[[ -f $FILE ]] || cat > $FILE <<EOF
alert tls any any -> any any (msg:"CDMCS TLS Self Signed Certificate"; flow:established; luajit:self-signed-cert.lua; tls.store; classtype:protocol-command-decode; sid:3000051; rev:1;)
alert tls any any -> any any (msg:"Recent certificate"; lua:new-cert.lua; tls.store; sid:3000052; rev:1;)
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

FILE=/var/lib/suricata/rules/new-cert.lua
[[ -f $FILE ]] || cat > $FILE <<EOF
function init (args)
    local needs = {}
    needs["tls"] = tostring(true)
    needs["flowint"] = {"cert-age"}
    return needs
end
function match(args)
    notbefore = TlsGetCertNotBefore()
    if not notbefore then
        return 0
    end
    if os.time() - notbefore <  3 * 3600  then
        ScFlowintSet(0, os.time() - notbefore)
        return 1
    end
    return 0
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
include: /etc/suricata/cdmcs-datasets.yaml
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
default-rule-path: /var/lib/suricata/rules
rule-files:
 -  suricata.rules
 -  custom.rules
 -  lua.rules
sensor-name: CDMCS
EOF

echo "Adding datasets for SURICATA"
FILE=/etc/suricata/cdmcs-datasets.yaml

grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
datasets:
  ua-seen:
    type: sha256
    state: /var/lib/suricata/ua-sha256-seen.lst
  dns-sha256-seen:
    type: sha256
    state: /var/lib/suricata/dns-sha256-seen.lst
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
      filetype: regular
      filename: alert.json
      community-id: yes
      community-id-seed: 0
      types:
        - alert:
            payload: no
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            http-body: no
            http-body-printable: yes
            metadata: yes
            tagged-packets: no
  - eve-log:
      enabled: 'yes'
      filetype: regular
      filename: eve.json
      redis:
        server: 127.0.0.1
        port: 6379
        async: true
        mode: list
        pipelining:
          enabled: yes
          batch-size: 10
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            http-body: yes
            http-body-printable: yes
            metadata: no
            tagged-packets: yes
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - files:
            force-magic: no
        - drop:
            alerts: yes
        - smtp:
            extended: yes
        - dnp3
        - nfs
        - smb
        - tftp
        - ikev2
        - krb5
        - dhcp:
            enabled: yes
            extended: yes
        - ssh
        - flow
  - eve-log:
      enabled: 'yes'
      filetype: syslog
      filename: eve.json
      prefix: "@cee: "
      identity: "suricata"
      facility: local5
      level: Info
      redis:
        server: 127.0.0.1
        port: 6379
        async: true
        mode: list
        pipelining:
          enabled: yes
          batch-size: 10
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            http-body: yes
            http-body-printable: yes
            metadata: no
            tagged-packets: yes
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - files:
            force-magic: no
        - drop:
            alerts: yes
        - smtp:
            extended: yes
        - dnp3
        - nfs
        - smb
        - tftp
        - ikev2
        - krb5
        - dhcp:
            enabled: yes
            extended: yes
        - ssh
        - stats:
            totals: yes
            threads: yes
            deltas: yes
        - flow
  - eve-log:
      enabled: 'yes'
      filetype: redis
      filename: eve.json
      redis:
        server: 127.0.0.1
        port: 6379
        async: true
        mode: list
        pipelining:
          enabled: yes
          batch-size: 10
      types:
        - alert:
            payload: no
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            http-body: no
            http-body-printable: yes
            metadata: yes
            tagged-packets: no
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - files:
            force-magic: no
        - drop:
            alerts: yes
        - smtp:
            extended: yes
        - dnp3
        - nfs
        - smb
        - tftp
        - ikev2
        - krb5
        - dhcp:
            enabled: yes
            extended: yes
        - ssh
        - flow
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
sleep 10
suricatasc -c "reload-rules" 
suricatasc -c "dataset-add ua-seen sha256 53c5f12948a236c0a34e4cb17c51a337ef61524cb4363023f242115f11555d1f"
suricatasc -c "dataset-add http-content-delivery string $(echo -n download.windowsupdate.com | base64)"
suricatasc -c "dataset-add http-content-delivery string $(echo -n security.debian.com | base64)"

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

echo "configuring moloch rules"
RULE_FILE="/data/moloch/etc/rules.conf"
grep "rules" $RULE_FILE || cat >> $RULE_FILE <<EOF
---
version: 1
rules:
  - name: "Drop tls"
    when: "fieldSet"
    fields:
      protocols:
      - tls
    ops:
      _maxPacketsToSave: 12
  - name: "Set custom protocol on certain hosts"
    when: "fieldSet"
    fields:
      protocols:
        - http
        - tls
      host.http:
        - testmyids.com
        - self-signed.badssl.com
    ops:
      "tags": "IDStest"
  - name: "Set custom protocol when obsering programming language package downloads"
    when: "fieldSet"
    fields:
      protocols:
        - tls
      host.http:
        - go.googlesource.com
        - files.pythonhosted.org
    ops:
      "protocols": "pkg-management"
EOF

echo "Configuring capture plugins"
sed -i -e 's,#wiseHost=127.0.0.1,wiseHost=127.0.0.1\nwiseCacheSecs=60\nplugins=wise.so;suricata.so\nsuricataAlertFile=/var/log/suricata/alert.json\nviewerPlugins=wise.js\nwiseTcpTupleLookups=true\nwiseUdpTupleLookups=true\n,g' config.ini
sed -i "/\[default\]/arulesFiles=$RULE_FILE" config.ini

echo "Configuring custom stuff"
grep "custom-fields" $FILE || cat >> $FILE <<EOF
[override-ips]
192.168.10.0/24=tag:private-net;country:PRIVATE;asn:AS0000 This is neat
10.0.2.0/24=tag:private-net;country:VIRTUALBOX;asn:AS0000 This is neat
EOF

grep "custom-fields" $FILE || cat >> $FILE <<EOF
[custom-fields]
cdmcs.name=kind:lotermfield;count:true;friendly:Name;db:cdmcs.name;help:Traffic owner
cdmcs.type=kind:lotermfield;count:true;friendly:Type;db:cdmcs.type;help:Traffic type
EOF

grep "custom-views" $FILE || cat >> $FILE <<EOF
[custom-views]
cdmcs=title:Cyber Defence Monitoring Course;require:cdmcs;fields:cdmcs.name,cdmcs.type
EOF

grep "wise-types" $FILE || cat >> $FILE <<EOF
[wise-types]
mac=db:srcMac;db:dstMac
EOF

grep "multi-viewer" $FILE || cat >> $FILE <<EOF
[multi-viewer]
elasticsearch=127.0.0.1:8200
viewPort = 8009
multiES = true
multiESPort = 8200
multiESHost = localhost
multiESNodes = ${EXPOSE}:9200
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

FILE=/etc/systemd/system/moloch-multies.service
grep "moloch-multies" $FILE || cat > $FILE <<EOF
[Unit]
Description=Moloch ES proxy for multi-viewer
After=network.target moloch-wise.service

[Service]
Type=simple
Restart=on-failure
ExecStart=/data/moloch/bin/node multies.js -c /data/moloch/etc/config.ini -n multi-viewer
WorkingDirectory=/data/moloch/viewer
SyslogIdentifier=moloch-multies

[Install]
WantedBy=multi-user.target
EOF

FILE=/etc/systemd/system/moloch-multi-viewer.service
grep "moloch-multi-viewer" $FILE || cat > $FILE <<EOF
[Unit]
Description=Moloch Viewer for proxying multiple clusters
After=network.target moloch-wise.service moloch-multies.service

[Service]
Type=simple
Restart=on-failure
ExecStart=/data/moloch/bin/node viewer.js -c /data/moloch/etc/config.ini -n multi-viewer
WorkingDirectory=/data/moloch/viewer
SyslogIdentifier=moloch-multi-viewer

[Install]
WantedBy=multi-user.target
EOF

FILE=/etc/systemd/system/moloch-capture.service
grep "moloch-capture" $FILE || cat > $FILE <<EOF
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
PIDFile=/var/run/capture.pid

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
for service in wise viewer multies multi-viewer capture ; do
  systemctl enable moloch-$service.service
  systemctl start moloch-$service.service
  systemctl status moloch-$service.service
done

sleep 2
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
sleep 3

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
docker ps -a | grep influx || docker run -dit \
  --name influx \
  -h influx \
  --network cdmcs \
  --restart unless-stopped \
  -p 8086:8086 \
    $DOCKER_INFLUXDB

# grafana
echo "Provisioning GRAFANA"
mkdir -p /etc/grafana/provisioning/dashboards/

DASHBOARDS=/vagrant/grafana-provision
if [ ! -d $DASHBOARDS ]; then
  DASHBOARDS=/home/vagrant/cdmcs/Moloch/vagrant/singlehost/grafana-provision
  git clone https://github.com/ccdcoe/cdmcs.git /home/vagrant/cdmcs
fi
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
    path: $DASHBOARDS
EOF

docker ps -a | grep grafana || docker run -dit \
  --name grafana \
  -h grafana \
  --network cdmcs \
  --restart unless-stopped \
  -p 3000:3000 \
  -v /etc/grafana/provisioning:/etc/grafana/provisioning \
  -v /vagrant:/vagrant \
  --log-driver syslog --log-opt tag="grafana" \
    $DOCKER_GRAFANA

sleep 10
echo "configuring grafana data sources"
curl -s -XPOST --user admin:admin $EXPOSE:3000/api/datasources -H "Content-Type: application/json" -d "{
    \"name\": \"telegraf\",
    \"type\": \"influxdb\",
    \"access\": \"proxy\",
    \"url\": \"http://influx:8086\",
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
  year = "2020"
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
  commands = ["$GOPATH/bin/ethflux $IFACE_PATTERN"]
  timeout = "5s"
  data_format = "influx"
EOF

FILE=/etc/telegraf/telegraf.d/moloch.conf
grep "CDMCS" $FILE || cat > $FILE <<EOF
[[inputs.procstat]]
  pid_finder = "pgrep"
  exe = "moloch-capture"
EOF

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

check_service telegraf

echo "making some noise"
while : ; do curl -s https://www.facebook.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s https://sysadminnid.tumblr.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s http://testmyids.com > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s -k https://self-signed.badssl.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do dig NS berylia.org @1.1.1.1 > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do dig NS berylia.org @8.8.8.8 > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &

echo "DONE :: start $start end $(date)"

echo "Sleeping 60 seconds for data to ingest."; sleep 60

echo "Provisioning KIBANA DASHBOARDS"
curl -s -XPOST "localhost:5601/api/saved_objects/_import" -H "kbn-xsrf: true" --form file=@/vagrant/export.ndjson

echo "Checking on moloch"
curl -ss -u vagrant:vagrant --digest "http://$EXPOSE:8005/sessions.csv?counts=0&date=1&fields=ipProtocol,totDataBytes,srcDataBytes,dstDataBytes,firstPacket,lastPacket,srcIp,srcPort,dstIp,dstPort,totPackets,srcPackets,dstPackets,totBytes,srcBytes,suricata.signature&length=1000&expression=suricata.signature%20%3D%3D%20EXISTS%21"
curl -ss -u vagrant:vagrant --digest "http://$EXPOSE:8005/unique.txt?exp=host.dns&counts=0&date=1&expression=tags%20%3D%3D%20bloom"

echo "Checking on suricata and elastic"
curl -s -XPOST localhost:9200/suricata-*/_search -H "Content-Type: application/json" -d '{"size": 1, "query": {"term": {"event_type": "alert"}}}' | jq .
curl -s -XPOST localhost:9200/suricata-*/_search -H "Content-Type: application/json" -d '
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "timestamp": {
              "gte": "now-1h",
              "lte": "now"
            }
          }
        }
      ]
    }
  },
  "aggs": {
    "events": {
      "terms": {
        "field": "event_type.keyword",
        "size": 20
      }
    },
    "alertTop10": {
      "terms": {
        "field": "alert.signature.keyword",
        "size": 10
      }
    }
  }
}
' | jq .
