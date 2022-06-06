#!/bin/bash

USER="vagrant"
PKGDIR=/vagrant/pkgs
HOME=/home/vagrant
PCAP_REPLAY=/srv/replay

if [[ -n $(ip link show | grep eth0) ]]; then
  # legacy naming
  IFACE_EXT="eth0"
  IFACE_INT="eth1"
  IFACE_PATTERN="eth"
elif [[ -n $(ip link show | grep ens1) ]]; then
  # vmware
  IFACE_EXT="ens192"
  IFACE_INT="ens192"
  IFACE_PATTERN="ens"
else
  # vbox
  IFACE_EXT="enp0s3"
  IFACE_INT="enp0s8"
  IFACE_PATTERN="enp"
fi

check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive|failed" && systemctl start $1.service
  systemctl status $1.service
}

check_service_noverify(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
}

# params
DEBUG=true
EXPOSE=127.0.0.1
WGET_PARAMS="-4 -q"

GOPATH=$HOME/go/
GOROOT=$HOME/.local/go
PATH=$PATH:/opt/arkime/bin:$GOROOT/bin:$GOPATH/bin

grep PATH /etc/environment || echo "export PATH=$PATH" >> /etc/environment

echo "Installing prerequisite packages..."
apt-get update && apt-get -y install \
  jq \
  wget \
  curl \
  tmux \
  unzip \
  pcregrep \
  python3-pip \
  python3-yaml \
  python-yaml \
  libpcre3-dev \
  libyaml-dev \
  uuid-dev \
  libmagic-dev \
  pkg-config \
  g++ \
  flex \
  bison \
  zlib1g-dev \
  libffi-dev \
  gettext \
  libgeoip-dev \
  make \
  libjson-perl \
  libbz2-dev \
  libwww-perl \
  libpng-dev \
  xz-utils \
  libffi-dev \
  libsnappy-dev \
  numactl \
  pcregrep \
  tcpreplay || exit 1

# versions
UBUNTU_VERSION="20.04"
ELASTIC_VERSION="7.17.4"
INFLUX_VERSION="1.8.3"
GRAFANA_VERSION="7.3.6"
TELEGRAF_VERSION="1.16.2"
GOLANG_VERSION="1.15.6"
ARKIME_VERSION="3.4.2"

ELA="elasticsearch-oss-${ELASTIC_VERSION}-amd64.deb"
KIBANA="kibana-oss-${ELASTIC_VERSION}-amd64.deb"
INFLUX="influxdb_${INFLUX_VERSION}_amd64.deb"
GRAFANA="grafana_${GRAFANA_VERSION}_amd64.deb"

TELEGRAF="telegraf_${TELEGRAF_VERSION}-1_amd64.deb"
GOLANG="go${GOLANG_VERSION}.linux-amd64.tar.gz"

DOCKER_ELA="docker.elastic.co/elasticsearch/elasticsearch:${ELASTIC_VERSION}"
DOCKER_KIBANA="docker.elastic.co/kibana/kibana:${ELASTIC_VERSION}"
DOCKER_LOGSTASH="docker.elastic.co/logstash/logstash:${ELASTIC_VERSION}"
DOCKER_FILEBEAT="docker.elastic.co/beats/filebeat:${ELASTIC_VERSION}"

DOCKER_INFLUXDB="influxdb:${INFLUX_VERSION}-alpine"
DOCKER_GRAFANA="grafana/grafana:${GRAFANA_VERSION}"

ARKIME_FILE="arkime_${ARKIME_VERSION}-1_amd64.deb"
ARKIME_LINK="https://s3.amazonaws.com/files.molo.ch/builds/ubuntu-${UBUNTU_VERSION}/${ARKIME_FILE}"

GOPHER_URL=$(curl --silent "https://api.github.com/repos/StamusNetworks/gophercap/releases/latest" | jq -r '.assets[] | select(.name|startswith("gopherCap-ubuntu-2004-")) | .browser_download_url')

ELASTSIC_MEM=512
LOGSTASH_MEM=512

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

sleep 15 # With pre-pulled docker images the next steps run before elastic has spun up.

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
      --host 0.0.0.0 \

echo "Provisioning RSYSLOG"
add-apt-repository -y ppa:adiscon/v8-stable
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

docker ps -a | grep logstash || docker run -dit \
  --name logstash \
  -h logstash \
  --network cdmcs \
  -v /etc/logstash/conf.d/:/usr/share/logstash/pipeline/ \
  -e "ES_JAVA_OPTS=-Xms${LOGSTASH_MEM}m -Xmx${LOGSTASH_MEM}m" \
  --restart unless-stopped \
    $DOCKER_LOGSTASH

docker stop logstash
sleep 5

echo "Provisioning Filebeat"

FILE=/etc/filebeat.yml
grep "CDMCS" $FILE || cat > $FILE <<EOF
# CDMCS
filebeat.inputs:
- type: log
  paths:
    - "/var/log/suricata/eve.json"
  json.keys_under_root: true
  json.add_error_key: true

processors:
- timestamp:
    field: timestamp
    layouts:
      - '2006-01-02T15:04:05Z'
      - '2006-01-02T15:04:05.999Z'
    test:
      - '2019-06-22T16:33:51Z'
      - '2019-11-18T04:59:51.123Z'

output.elasticsearch:
  hosts: ["elastic:9200"]
  index: "filebeat-%{+yyyy.MM.dd}"
  bulk_max_size: 10000

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

setup.template:
  name: 'filebeat'
  pattern: 'filebeat-*'
  enabled: false

setup.ilm.enabled: false
EOF

docker ps -a | grep filebeat || docker run -dit \
  --name filebeat \
  -h filebeat \
  --network cdmcs \
  -v /var/log/suricata:/var/log/suricata:ro \
  -v /var/log/filebeat:/var/log/filebeat:rw \
  -v /etc/filebeat.yml:/etc/filebeat.yml \
  --restart unless-stopped \
    $DOCKER_FILEBEAT run -c /etc/filebeat.yml

echo "Configuring interfaces"

FILE=/usr/sbin/replay_iface
[[ -f $FILE ]] || cat > $FILE <<EOF
#!/bin/sh
ip link add capture0 type veth peer name replay0
ip link set dev capture0 mtu 9000
ip link set dev replay0 mtu 9000
ip link set capture0 up
ip link set replay0 up
EOF
chmod 755 $FILE

FILE=/etc/systemd/system/virtIface.service
[[ -f $FILE ]] || cat > $FILE <<EOF
[Unit]
Description=capture interface
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/var/run/
ExecStart=/usr/sbin/replay_iface
Type=oneshot

[Install]
WantedBy=multi-user.target
EOF

check_service virtIface

delim=";"; ifaces=""; for item in `ls /sys/class/net/ | egrep '^eth|ens|eno|enp|capture'`; do ifaces+="$item$delim"; done ; ifaces=${ifaces%"$deli$delim"}

for iface in ${ifaces//;/ }; do
  echo "Setting capture params for $iface"
  for i in rx tx tso gso gro tx nocache copy sg rxvlan; do ethtool -K $iface $i off > /dev/null 2>&1; done
done

echo "Provisioning SURICATA"
# suricata
install_suricata_from_ppa(){
  add-apt-repository -y ppa:oisf/suricata-stable > /dev/null 2>&1 \
  && apt-get update > /dev/null \
  && apt-get install -y suricata > /dev/null
}

suricata -V || install_suricata_from_ppa
pip3 install --upgrade suricata-update

touch  /etc/suricata/threshold.config
mkdir -p /var/lib/suricata/rules
[[ -f /var/lib/suricata/rules/scirius.rules ]] || touch /etc/suricata/rules/scirius.rules
[[ -f /var/lib/suricata/rules/suricata.rules ]] || touch /etc/suricata/rules/suricata.rules

FILE=/var/lib/suricata/rules/custom.rules
[[ -f $FILE ]] || cat > $FILE <<EOF
alert http \$HOME_NET any -> \$EXTERNAL_NET any (msg:"CDMCS: External Windows executable download"; flow:established,to_server; content:"GET "; uricontent:".exe"; nocase; classtype:policy-violation; sid:3000001; rev:1; metadata:created_at 2018_01_19, updated_at 2018_01_19;) 
alert dns any any -> any any (msg:"CDMCS: DNS request for Facebook"; dns.query; content:"facebook"; classtype:policy-violation; sid:3000002; rev:1; metadata:created_at 2018_01_19, updated_at 2018_01_19;)
alert tls any any -> any any (msg:"CDMCS: Facebook certificate detected"; tls.sni; content: "facebook"; classtype:policy-violation; sid:3000003; rev:1; metadata:created_at 2018_01_19, updated_at 2018_01_19;)
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

echo "Adding datasets for SURICATA"
FILE=/etc/suricata/cdmcs-datasets.yaml

grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
datasets:
  defaults:
    memcap: 10mb
    hashsize: 1024
  ua-seen:
    type: sha256
    state: /var/lib/suricata/ua-sha256-seen.lst
  dns-sha256-seen:
    type: sha256
    state: /var/lib/suricata/dns-sha256-seen.lst
    memcap: 100mb
    hashsize: 4096
EOF

FILE=/var/lib/suricata/rules/datasets.rules
[[ -f $FILE ]] || cat > $FILE <<EOF
alert http any any -> \$EXTERNAL_NET any (msg:"CDMCS: Collect unique user-agents"; http.user_agent; dataset:set,http-user-agents, type string, state /var/lib/suricata/http-user-agents.lst; bypass; sid:3000007; rev:1; metadata:created_at 2020_02_28, updated_at 2020_02_28;)
alert http any any -> any any (msg:"CDMCS: Listed UA seen"; http.user_agent; to_sha256; dataset:isset,ua-seen; classtype:policy-violation; sid:3000004; rev:1; metadata:created_at 2020_01_29, updated_at 2020_01_29;)
alert dns any any -> any any (msg:"CDMCS: Listed DNS hash seen"; dns.query; to_sha256; dataset:isset,dns-sha256-seen; classtype:policy-violation; sid:3000005; rev:1; metadata:created_at 2020_01_29, updated_at 2020_01_29;)
EOF

echo "Adding detects for SURICATA"
FILE=/etc/suricata/cdmcs-detect.yaml
grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
af-packet:
  - interface: ${IFACE_EXT}
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: capture0
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: /var/lib/suricata/rules
rule-files:
 -  suricata.rules
 -  custom.rules
 -  lua.rules
 -  datasets.rules
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

echo "Adding includes for SURICATA"
FILE=/etc/suricata/suricata.yaml
grep "cdmcs" $FILE || cat >> $FILE <<EOF
include: /etc/suricata/cdmcs-detect.yaml
include: /etc/suricata/cdmcs-logging.yaml
include: /etc/suricata/cdmcs-datasets.yaml
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

echo "Provision arkime"
cd $PKGDIR
[[ -f $ARKIME_FILE ]] || wget $WGET_PARAMS $ARKIME_LINK

dpkg -s arkime || dpkg -i $ARKIME_FILE
apt-get -f -y install

echo "Configuring arkime"
cd /opt/arkime/etc
FILE=/opt/arkime/etc/config.ini
[[ -f config.ini ]] || cp config.ini.sample $FILE
sed -i "s/ARKIME_ELASTICSEARCH/http:\/\/localhost:9200/g"  config.ini
sed -i "s/ARKIME_INTERFACE/$ifaces/g"             config.ini
sed -i "s/ARKIME_INSTALL_DIR/\/opt\/arkime/g"    config.ini
sed -i "s/ARKIME_INSTALL_DIR/\/opt\/arkime/g"    config.ini
sed -i "s/ARKIME_PASSWORD/test123/g"              config.ini

echo "configuring arkime rules"
RULE_FILE="/opt/arkime/etc/rules.conf"
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
TAGGER_FILE="/opt/arkime/etc/tagger.txt"
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
redisURL=redis://127.0.0.1:6379/1

[file:ip]
file=${TAGGER_FILE}
tags=ipwise
type=ip
format=tagger

[redis:ip]
url=redis://127.0.0.1:6379/0
redisURL=redis://127.0.0.1:6379/0
tags=redis
type=ip
format=tagger
EOF

echo "Configuring databases"
cd /opt/arkime/db
if [[ `./db.pl localhost:9200 info | grep "DB Version" | cut -d ":" -f2 | tr -d " "` -eq -1 ]]; then
  echo "INIT" | ./db.pl localhost:9200 init
fi

cd /opt/arkime/bin
./arkime_update_geo.sh > /dev/null 2>&1
chown nobody:daemon /data/arkime/raw

echo "Configuring system limits"
ulimit -l unlimited
grep memlock /etc/security/limits.conf || echo "nofile 128000 - memlock unlimited" >> /etc/security/limits.conf
mkdir /opt/arkime/raw && chown nobody:daemon /opt/arkime/raw

echo "Configuring systemd services"

FILE=/etc/systemd/system/arkime-wise.service
grep "arkime-wise" $FILE || cat > $FILE <<EOF
[Unit]
Description=arkime WISE
After=network.target

[Service]
Type=simple
Restart=on-failure
ExecStart=/opt/arkime/bin/node wiseService.js -c /opt/arkime/etc/wiseService.ini
WorkingDirectory=/opt/arkime/wiseService
SyslogIdentifier=arkime-wise

[Install]
WantedBy=multi-user.target
EOF

FILE=/etc/systemd/system/arkime-viewer.service
grep "arkime-viewer" $FILE || cat > $FILE <<EOF
[Unit]
Description=arkime Viewer
After=network.target arkime-wise.service

[Service]
Type=simple
Restart=on-failure
ExecStart=/opt/arkime/bin/node viewer.js -c /opt/arkime/etc/config.ini
WorkingDirectory=/opt/arkime/viewer
SyslogIdentifier=arkime-viewer

[Install]
WantedBy=multi-user.target
EOF

FILE=/etc/systemd/system/arkime-capture.service
grep "arkime-capture" $FILE || cat > $FILE <<EOF
[Unit]
Description=arkime Capture
After=network.target arkime-wise.service arkime-viewer.service

[Service]
Type=simple
Restart=on-failure
#ExecStartPre=-/opt/arkime/bin/start-capture-interfaces.sh
ExecStart=/usr/bin/numactl --cpunodebind=0 --membind=0 /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini --host $(hostname)
WorkingDirectory=/opt/arkime
LimitCORE=infinity
LimitMEMLOCK=infinity
SyslogIdentifier=arkime-capture
PIDFile=/var/run/capture.pid

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
for service in wise viewer capture ; do
  echo starting $service
  systemctl enable arkime-$service.service
  systemctl start arkime-$service.service
  systemctl status arkime-$service.service
  sleep 3
done

sleep 2
pgrep capture || exit 1

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

def get_arkime_capture_parent():
    procs = {p.pid: p.info for p in psutil.process_iter(attrs=['pid', 'name', 'username'])}
    parent = {k: v for k, v in procs.items() if "arkime-capture" in v["name"]}
    parent = list(parent.values())[0]["pid"]
    parent = psutil.Process(pid=parent)
    return parent

def get_arkime_workers(parent):
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

    cap_pattern = re.compile("^arkime-(?:capture|simple|af\d+-\d+)$")
    pkt_pattern = re.compile("^arkime-pkt\d+$")

    parent = get_arkime_capture_parent()
    workers = get_arkime_workers(parent)

    cap_threads = [t for t in workers if cap_pattern.match(t["name"])]
    pkt_threads = [t for t in workers if pkt_pattern.match(t["name"])]

    if len(pkt_threads) > len(worker_threads):
        print("Too many arkime workers for {} cpu threads".format(len(worker_threads)))
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
# su - vagrant -c "python3 $FILE"

echo "Adding viewer user"
cd /opt/arkime/viewer && ../bin/node addUser.js vagrant vagrant vagrant --admin
sleep 3

# parliament
PARLIAMENTPASSWORD=admin
if curl ${EXPOSE}:8005/eshealth.json > /dev/null 2>&1 ; then
   if curl ${EXPOSE}:8008 > /dev/null 2>&1; then
     echo "parliament: already in use ${EXPOSE}:8008"
   else
      echo "parliament: preparing ..."  
      cd /opt/arkime/parliament
      [ -f parliament.json ] && mv parliament.json parliament.json.$(date +%s)
      /opt/arkime/bin/node parliament.js > >(logger -p daemon.info -t capture) 2> >(logger -p daemon.err -t capture) & sleep 1 ; echo $! > /var/run/parliament.pid  

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
  DASHBOARDS=/home/vagrant/cdmcs/Arkime/vagrant/singlehost/grafana-provision
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

FILE=/etc/telegraf/telegraf.d/arkime.conf
grep "CDMCS" $FILE || cat > $FILE <<EOF
[[inputs.procstat]]
  pid_finder = "pgrep"
  exe = "arkime-capture"
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

echo "pulling some replay PCAPs"

mkdir -p $PCAP_REPLAY
cd $PCAP_REPLAY
[[ -f 2021-01-06-Remcos-RAT-infection.pcap.zip ]] || wget $WGET_PARAMS  https://malware-traffic-analysis.net/2021/01/06/2021-01-06-Remcos-RAT-infection.pcap.zip
[[ -f 2021-01-05-PurpleFox-EK-and-post-infection-traffic.pcap.zip ]] || wget $WGET_PARAMS https://malware-traffic-analysis.net/2021/01/05/2021-01-05-PurpleFox-EK-and-post-infection-traffic.pcap.zip
[[ -f 2021-01-04-Emotet-infection-with-Trickbot-traffic.pcap.zip ]] || wget $WGET_PARAMS https://malware-traffic-analysis.net/2021/01/04/2021-01-04-Emotet-infection-with-Trickbot-traffic.pcap.zip

for pcap in $(find $PCAP_REPLAY/ -type f -name '*.pcap.zip') ; do
  echo unpacking $pcap
  unzip -P infected ${pcap}
done

FILE=$PCAP_REPLAY/gopher.yml
grep "CDMCS" $FILE || cat > $FILE <<EOF
# CDMCS
global:
  dump:
    json: ${PCAP_REPLAY}/gopher.json
  file:
    regexp: "2021"
map:
  dir:
    src: ${PCAP_REPLAY}
  file:
    suffix: pcap
    workers: 2
replay:
  disable_wait: true
  loop:
    count: 1
    infinite: true
  out:
    bpf: ""
    interface: replay0
  time:
    from: ""
    modifier: "1"
    scale:
      duration: 1h0m0s
      enabled: true
    to: ""
tarball:
  dryrun: false
  in:
    file: ""
  out:
    dir: ""
    gzip: false
EOF

FILE=$PCAP_REPLAY/gopherCap.gz
[[ -f $FILE ]] || wget $WGET_PARAMS -O $FILE $GOPHER_URL
gunzip $FILE
chmod 755 ./gopherCap
./gopherCap --config example.yml exampleConfig
./gopherCap --config gopher.yml map
pgrep gopherCap || ./gopherCap --config gopher.yml replay 2>/dev/null &

#for pcap in $(find $PCAP_REPLAY/ -type f -name '*.pcap') ; do
#  echo replaying $pcap
#  tcpreplay --pps=100 --loop=100000 -i replay0 ${pcap} &
#done

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

echo "Checking on arkime"
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
