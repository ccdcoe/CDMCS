#!/bin/bash

USER="vagrant"
PKGDIR=/vagrant/pkgs
HOME=/home/vagrant
PCAP_REPLAY=/srv/replay

# This script is meant to be run on vagrant box images, but let's compensate
[ -d "$HOME" ] || useradd -m -G sudo $USER && mkdir -p $PKGDIR && chown -R $USER: /vagrant

# Determine "Predictable Network Interface Names"
if [[ -n $(ip link show | grep eth0) ]]; then
  # legacy naming
  IFACE_EXT="eth0"
  IFACE_INT="eth1"
  IFACE_PATTERN="eth"
elif [[ -n $(ip link show | grep ens1) ]]; then
  # vmware (older Ubuntu and Debian?)
  IFACE_EXT="ens192"
  IFACE_INT="ens192"
  IFACE_PATTERN="ens"
elif [[ -n $(ip link show | grep enp11) ]]; then
  # vmware (Ubuntu 22.04)
  IFACE_EXT="enp11s0"
  IFACE_INT="enp11s0"
  IFACE_PATTERN="enp"
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
UBUNTU_VERSION="2204"
ELASTIC_VERSION="8.13.4"
INFLUX_VERSION="2.7.1"
GRAFANA_VERSION="9.5.3"
TELEGRAF_VERSION="1.26.3"
GOLANG_VERSION="1.22.3"
ARKIME_VERSION="5.1.2"
PIKKSILM_VERSION="0.7.0"

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
ARKIME_LINK="https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/arkime_${ARKIME_VERSION}-1.ubuntu${UBUNTU_VERSION}_amd64.deb"
ARKIME_JA4_LINK="https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/ja4plus.amd64.so"

GOPHER_URL=$(curl --silent "https://api.github.com/repos/StamusNetworks/gophercap/releases/latest" | jq -r '.assets[] | select(.name=="gopherCap.gz") | .browser_download_url')
PIKKSILM_URL=$(curl -ss -H "Accept: application/vnd.github.v3+json" https://api.github.com/repos/markuskont/pikksilm/releases | jq -r ".[] | select(.tag_name==\"v${PIKKSILM_VERSION}\") | .assets | .[] | select(.name==\"pikksilm_${PIKKSILM_VERSION}_linux_amd64.tar.gz\") | .browser_download_url")

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
    redis

# elastic
echo "Provisioning ELASTICSEARCH"
docker ps -a | grep elastic || docker run -dit \
  --name elastic \
  -h elastic \
  --network cdmcs \
  -e "ES_JAVA_OPTS=-Xms${ELASTSIC_MEM}m -Xmx${ELASTSIC_MEM}m" \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  --restart unless-stopped \
  -p 9200:9200 \
    $DOCKER_ELA 

sleep 25 # With pre-pulled docker images the next steps run before elastic has spun up.

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

docker ps -a | grep evebox | docker run -tid \
  --network cdmcs \
  --name evebox \
  --restart unless-stopped \
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

delim=";"; ifaces=""; for item in `ls /sys/class/net/ | egrep '^eth|ens|eno|enp|capture|monitoring'`; do ifaces+="$item$delim"; done ; ifaces=${ifaces%"$deli$delim"}

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
    state: ua-sha256-seen.lst
  dns-sha256-seen:
    type: sha256
    state: dns-sha256-seen.lst
    memcap: 100mb
    hashsize: 4096
EOF

FILE=/var/lib/suricata/rules/datasets.rules
[[ -f $FILE ]] || cat > $FILE <<EOF
alert http any any -> \$EXTERNAL_NET any (msg:"CDMCS: Collect unique user-agents"; http.user_agent; dataset:set,http-user-agents, type string, state http-user-agents.lst; bypass; sid:3000007; rev:1; metadata:created_at 2020_02_28, updated_at 2020_02_28;)
alert http any any -> any any (msg:"CDMCS: Listed UA seen"; http.user_agent; to_sha256; dataset:isset,ua-seen; classtype:policy-violation; sid:3000004; rev:1; metadata:created_at 2020_01_29, updated_at 2020_01_29;)
alert dns any any -> any any (msg:"CDMCS: Listed DNS hash seen"; dns.query; to_sha256; dataset:isset,dns-sha256-seen; classtype:policy-violation; sid:3000005; rev:1; metadata:created_at 2020_01_29, updated_at 2020_01_29;)
EOF

mkdir -p /var/lib/suricata/data
touch /var/lib/suricata/rules/http-user-agents.lst

echo "Adding detects for SURICATA"
FILE=/etc/suricata/cdmcs-detect.yaml
grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
security:
  # if true, prevents process creation from Suricata by calling
  # setrlimit(RLIMIT_NPROC, 0)
  limit-noproc: true
  # Use landlock security module under Linux
  landlock:
    enabled: no
    directories:
      #write:
      #  - /var/run/
      # /usr and /etc folders are added to read list to allow
      # file magic to be used.
      read:
        - /usr/
        - /etc/
        - /etc/suricata/
  lua:
    # Allow Lua rules. Disabled by default.
    allow-rules: true

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
            metadata: yes
            tagged-packets: yes
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - files:
            force-magic: no
        - smtp:
            extended: yes
        - dnp3
        - nfs
        - smb
        - tftp
        - ike
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
            metadata: yes
            tagged-packets: yes
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - files:
            force-magic: no
        - smtp:
            extended: yes
        - dnp3
        - nfs
        - smb
        - tftp
        - ike
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
        - smtp:
            extended: yes
        - dnp3
        - nfs
        - smb
        - tftp
        - ike
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
include:
- /etc/suricata/cdmcs-detect.yaml
- /etc/suricata/cdmcs-logging.yaml
- /etc/suricata/cdmcs-datasets.yaml
EOF

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

echo "Provisioning Pikksilm"

mkdir -p /var/lib/pikksilm
grep pikksilm /etc/passwd || useradd --system -d /var/lib/pikksilm pikksilm
chown pikksilm /var/lib/pikksilm

cd $PKGDIR
echo "Downloading pikksilm from ${PIKKSILM_URL}"
wget -O pikksilm.tar.gz $PIKKSILM_URL
tar -xzf pikksilm.tar.gz -C /usr/local/bin

which pikksilm || exit 1
pikksilm --config /etc/pikksilm.toml config

FILE=/etc/systemd/system/pikksilm.service
grep "pikksilm" $FILE || cat > $FILE <<EOF
[Unit]
Description=Pikksilm EDR to NDR correlator and enrichment
After=network.target

[Service]
Type=simple
Restart=on-failure
EnvironmentFile=-/etc/pikksilm.env
ExecStart=/usr/local/bin/pikksilm --config /etc/pikksilm.yaml run
WorkingDirectory=/
User=pikksilm
Group=daemon

[Install]
WantedBy=multi-user.target
EOF

check_service pikksilm
sleep 3

journalctl -u pikksilm.service --output cat -n 10

echo "Provision arkime from $ARKIME_LINK"
cd $PKGDIR
[[ -f $ARKIME_FILE ]] || wget -O $ARKIME_FILE $WGET_PARAMS $ARKIME_LINK

dpkg -s arkime || dpkg -i $ARKIME_FILE
apt-get -f -y install

echo "Configuring arkime"
cd /opt/arkime/etc
FILE=/opt/arkime/etc/config.ini
[[ -f config.ini ]] || cp config.ini.sample $FILE
sed -i "s/ARKIME_ELASTICSEARCH/http:\/\/localhost:9200/g"   $FILE
sed -i "s/ARKIME_INTERFACE/$ifaces/g"                       $FILE
sed -i "s/ARKIME_INSTALL_DIR/\/opt\/arkime/g"               $FILE
sed -i "s/ARKIME_INSTALL_DIR/\/opt\/arkime/g"               $FILE
sed -i "s/ARKIME_PASSWORD/test123/g"                        $FILE

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
  - name: "Set custom protocol when observing programming language package downloads"
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

echo "Downloading Arkime JA4 support"
cd /opt/arkime/plugins
wget $ARKIME_JA4_LINK
cd -

echo "Configuring capture plugins"
sed -i -e 's,#wiseHost=127.0.0.1,wiseHost=127.0.0.1\nwiseCacheSecs=60\nplugins=ja4plus.amd64.so;wise.so;suricata.so\nsuricataAlertFile=/var/log/suricata/alert.json\nviewerPlugins=wise.js\nwiseTcpTupleLookups=true\nwiseUdpTupleLookups=true\n,g' $FILE
sed -i "/\[default\]/arulesFiles=$RULE_FILE" $FILE
sed -i "/\[default\]/asnapLen=65536" $FILE

echo "Configuring custom stuff"
grep "custom-fields" $FILE || cat >> $FILE <<EOF
[override-ips]
192.168.56.0/24=tag:private-net;country:PRIVATE;asn:AS0000 This is neat
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
sysmon=title:Sysmon correlation;require:sysmon;fields:sysmon.parentprocessname,sysmon.parentprocesspid,sysmon.processname,sysmon.processpid,sysmon.username,sysmon.hostname,sysmon.hostip,sysmon.hostmac
EOF

grep "wise-types" $FILE || cat >> $FILE <<EOF
[wise-types]
communityid=communityId
EOF

echo "Adding custom node sections"
grep "polar" $FILE || cat >> $FILE <<EOF
[polar]
pcapReadMethod=pcap-over-ip-server
viewPort=8006
simpleCompression=none
EOF

echo "Configuring wise"
TAGGER_FILE="/opt/arkime/etc/tagger.txt"
[[ -f $TAGGER_FILE ]] || cat > $TAGGER_FILE <<EOF
#field:cdmcs.name;shortcut:0
#field:cdmcs.type;shortcut:1
192.168.56.11;0=local
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

grep correlation wiseService.ini || cat >> wiseService.ini <<EOF
[redis:sysmon_proc]
url=redis://:password@127.0.0.1:6379/1
redisURL=redis://:password@127.0.0.1:6379/1
tags=correlation
type=communityid
format=json
template=1:%key%
keyPath=network.community_id
fields=field:sysmon.processname;db:sysmon.processname;kind:termfield;friendly:Process Name;shortcut:process.name\nfield:sysmon.username;db:sysmon.username;kind:termfield;friendly:User;shortcut:user.name\nfield:sysmon.hostname;db:sysmon.hostname;kind:termfield;friendly:Host Name;shortcut:host.name\nfield:sysmon.processpid;db:sysmon.processpid;kind:integer;friendly:Process PID;shortcut:process.pid\nfield:sysmon.hostip;db:sysmon.hostip;kind:ip;friendly:Host IP-s;shortcut:host.ip\nfield:sysmon.hostmac;db:sysmon.hostmac;kind:termfield;friendly:Host MAC;shortcut:host.mac
redisMethod=lpop

EOF

grep connection wiseService.ini || cat >> wiseService.ini <<EOF
[redis:sysmonevent1]
url=redis://:password@127.0.0.1:6379/2
redisURL=redis://:password@127.0.0.1:6379/2
tags=connection
type=communityid
format=json
template=1:%key%
keyPath=network.community_id
fields=field:sysmon.parentprocessname;db:sysmon.parentprocessname;kind:termfield;friendly:Parent Process Name;shortcut:process.parent.name\nfield:sysmon.parentprocesspid;db:sysmon.parentprocesspid;kind:termfield;friendly:Parent Process PID;shortcut:process.parent.pid\nfield:sysmon.processmd5;db:sysmon.processmd5;kind:termfield;friendly:Process MD5;shortcut:hash.md5\nfield:sysmon.processargs;db:sysmon.processargs;kind:textfield;friendly:Process Arguments;shortcut:process.command_line\nfield:sysmon.processintlevel;db:sysmon.processintlevel;kind:termfield;friendly:Process Integrity Level;shortcut:winlog.event_data.IntegrityLevel\n
redisMethod=lpop

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
# To survive a reboot, we need docker stuff to be up before running WISE
After=network.target containerd.service docker.service

[Service]
Type=simple
Restart=on-failure
# Elastic is slow to start up
RestartSec=15
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
# Elastic is slow to start up
RestartSec=15
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
# Elastic is slow to start up
RestartSec=15
#ExecStartPre=-/opt/arkime/bin/start-capture-interfaces.sh
ExecStart=/opt/arkime/bin/capture -c /opt/arkime/etc/config.ini --host $(hostname)
WorkingDirectory=/opt/arkime
LimitCORE=infinity
LimitMEMLOCK=infinity
SyslogIdentifier=arkime-capture

[Install]
WantedBy=multi-user.target
EOF

FILE=/etc/systemd/system/arkime-viewer-polar.service
grep "arkime-viewer" $FILE || cat > $FILE <<EOF
[Unit]
Description=arkime Viewer for Polar
After=network.target arkime-wise.service arkime-viewer.service

[Service]
Type=simple
Restart=on-failure
# Elastic is slow to start up
RestartSec=15
ExecStart=/opt/arkime/bin/node viewer.js -c /opt/arkime/etc/config.ini --node polar
WorkingDirectory=/opt/arkime/viewer
SyslogIdentifier=arkime-viewer

[Install]
WantedBy=multi-user.target
EOF

FILE=/etc/systemd/system/arkime-capture-polar.service
grep "arkime-capture-polar" $FILE || cat > $FILE <<EOF
[Unit]
Description=arkime Capture for Polar
After=network.target arkime-wise.service arkime-viewer.service arkime-capture.service

[Service]
Type=simple
Restart=on-failure
# Elastic is slow to start up
RestartSec=15
#ExecStartPre=-/opt/arkime/bin/start-capture-interfaces.sh
ExecStart=/opt/arkime/bin/capture -c /opt/arkime/etc/config.ini --host $(hostname) --node polar
WorkingDirectory=/opt/arkime
LimitCORE=infinity
LimitMEMLOCK=infinity
SyslogIdentifier=arkime-capture

[Install]
WantedBy=multi-user.target
EOF

FILE=/etc/systemd/system/arkime-parliament.service
grep "arkime-parliament" $FILE || cat > $FILE <<EOF
[Unit]
Description=arkime Parliament
After=network.target arkime-wise.service arkime-viewer.service arkime-capture.service

[Service]
Type=simple
Restart=on-failure
# Elastic is slow to start up
RestartSec=15
ExecStart=/opt/arkime/bin/node parliament.js
WorkingDirectory=/opt/arkime/parliament
PIDFile=/var/run/parliament.pid
LimitCORE=infinity
LimitMEMLOCK=infinity
SyslogIdentifier=arkime-parliament

[Install]
WantedBy=multi-user.target
EOF

for service in wise viewer capture parliament; do
  # delete the default service file
  rm /etc/systemd/system/arkime$service.service # delete the default service file
done

systemctl daemon-reload
for service in wise viewer capture capture-polar viewer-polar; do
  echo starting $service
  check_service arkime-$service
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
      check_service arkime-parliament
      sleep 3

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

echo "Setting up Cont3xt"
/opt/arkime/bin/Configure --cont3xt
FILE=/opt/arkime/etc/cont3xt.ini
sed -i "s/elasticsearch=/elasticsearc=http:\/\/localhost:9200/g"    $FILE
sed -i "s/ARKIME_PASSWORD/test123/g"                                $FILE

mkdir /opt/arkime/logs
systemctl restart arkimecont3xt

echo "Provisioning PolarProxy"
mkdir /opt/PolarProxy
cd /opt/PolarProxy
wget -O polarproxy.tar.gz 'https://www.netresec.com/?download=PolarProxy'
tar -zxvf polarproxy.tar.gz
mkdir /var/log/PolarProxy
cd -

FILE=/etc/systemd/system/PolarProxy.service
grep "PolarProxy" $FILE || cat > $FILE <<EOF
[Unit]
Description=PolarProxy TLS pcap logger
After=network.target

[Service]
SyslogIdentifier=PolarProxy
Type=simple
WorkingDirectory=/opt/PolarProxy
ExecStart=/opt/PolarProxy/PolarProxy -v -p 10443,80,443 -x /var/log/PolarProxy/polarproxy.cer -f /var/log/PolarProxy/proxyflows.log -o /var/log/PolarProxy/ --certhttp 10080 --socks 1080 --httpconnect 8080 --allownontls --insecure --pcapoveripconnect 127.0.0.1:57012
KillSignal=SIGINT
FinalKillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF
check_service PolarProxy

# Jupyterlab
echo "Provisioning Jupyterlab"
pip3 install jupyterlab jedi-language-server

FILE=/etc/systemd/system/jupyterlab.service
grep "jupyterlab" $FILE || cat > $FILE <<EOF
[Unit]
Description=jupyterlab
After=network.target

[Service]
Type=simple
User=$USER
Group=$USER
ExecStart=/usr/local/bin/jupyter lab -y --ip 0.0.0.0 --NotebookApp.token="$USER" --no-browser
Restart=on-failure
RestartSec=5
StartLimitBurst=10
WorkingDirectory=/vagrant
PIDFile=/var/run/jupyterlab.pid
SyslogIdentifier=jupyterlab

[Install]
WantedBy=multi-user.target
EOF
check_service jupyterlab

# echo "pulling some replay PCAPs"

# mkdir -p $PCAP_REPLAY
# cd $PCAP_REPLAY
# [[ -f 2021-01-06-Remcos-RAT-infection.pcap.zip ]] || wget $WGET_PARAMS  https://malware-traffic-analysis.net/2021/01/06/2021-01-06-Remcos-RAT-infection.pcap.zip
# [[ -f 2021-01-05-PurpleFox-EK-and-post-infection-traffic.pcap.zip ]] || wget $WGET_PARAMS https://malware-traffic-analysis.net/2021/01/05/2021-01-05-PurpleFox-EK-and-post-infection-traffic.pcap.zip
# [[ -f 2021-01-04-Emotet-infection-with-Trickbot-traffic.pcap.zip ]] || wget $WGET_PARAMS https://malware-traffic-analysis.net/2021/01/04/2021-01-04-Emotet-infection-with-Trickbot-traffic.pcap.zip

# for pcap in $(find $PCAP_REPLAY/ -type f -name '*.pcap.zip') ; do
#   echo unpacking $pcap
#   unzip -P infected ${pcap}
# done

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

# FILE=$PCAP_REPLAY/gopherCap.gz
# [[ -f $FILE ]] || wget $WGET_PARAMS -O $FILE $GOPHER_URL
# gunzip $FILE
# chmod 755 ./gopherCap
# ./gopherCap --config example.yml exampleConfig
# ./gopherCap --config gopher.yml map
# pgrep gopherCap || ./gopherCap --config gopher.yml replay 2>/dev/null &

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

curl -k --connect-to www.netresec.com:443:127.0.0.1:10443 https://www.netresec.com/ > /dev/null

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

journalctl -u arkime-capture.service --output cat -n 10
