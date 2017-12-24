check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive" && systemctl start $1.service
  systemctl status $1.service
}

# params
DEBUG=true
PROXY=http://192.168.10.1:3128
PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"

# versions
ELA="elasticsearch-6.1.1.deb"
# 6.1.1 index management was broken for me
KIBANA="kibana-6.0.1-amd64.deb"
LOGSTASH="logstash-6.1.1.deb"
INFLUX="influxdb_1.4.2_amd64.deb"
TELEGRAF="telegraf_1.5.0-1_amd64.deb"

# basic OS config
start=$(date)

FILE=/etc/sysctl.conf
grep "disable_ipv6" $FILE || cat >> $FILE <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p

#FILE=/etc/profile
#grep "proxy" $FILE || cat >> $FILE <<EOF
#http_proxy=$PROXY
#https_proxy=$PROXY
#export http_proxy
#export https_proxy
#EOF
#source /etc/profile

FILE=/etc/apt/apt.conf.d/99force-ipv4
[[ -f $FILE ]] ||  echo 'Acquire::ForceIPv4 "true";' | sudo tee $FILE
export DEBIAN_FRONTEND=noninteractive
mkdir -p /vagrant/pkgs

# basic software
#apt-get update > /dev/null && apt-get install curl htop vim tmux > /dev/null

# suricata
install_suricata_from_ppa(){
  add-apt-repository ppa:oisf/suricata-stable > /dev/null 2>&1 \
  && apt-get update > /dev/null \
  && apt-get install -y suricata > /dev/null
}
echo "Provisioning SURICATA"
suricata -V || install_suricata_from_ppa

[[ -f /etc/suricata/rules/scirius.rules ]] || touch /etc/suricata/rules/scirius.rules
if $DEBUG ; then ip addr show; fi
systemctl stop suricata
FILE=/etc/suricata/suricata.yaml
grep "Amstelredamme" $FILE || cat >> $FILE <<EOF
# Amstelredamme added by vagrant
af-packet:
  - interface: enp0s3
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: enp0s8
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
  - interface: eth0
    cluster-id: 96
    cluster-type: cluster_flow
    defrag: yes
  - interface: eth1
    cluster-id: 95
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: /etc/suricata/rules
rule-files:
 - scirius.rules
sensor-name: suricata
EOF

touch  /etc/suricata/threshold.config
if $DEBUG ; then suricata -T -vvv; fi

check_service suricata

# java
install_oracle_java() {
  echo "Installing oracle Java"
  echo 'oracle-java8-installer shared/accepted-oracle-license-v1-1 boolean true' | debconf-set-selections \
  && add-apt-repository ppa:webupd8team/java > /dev/null 2>&1 \
  && apt-get update > /dev/null \
  && apt-get -y install oracle-java8-installer > /dev/null
}
echo "Provisioning JAVA"
java -version || install_oracle_java

# elastic
echo "Provisioning ELASTICSEARCH"
cd $PKGDIR
[[ -f $ELA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/elasticsearch/$ELA -O $ELA
dpkg -i $ELA > /dev/null 2>&1

check_service elasticsearch

# kibana
echo "Provisioning KIBANA"
cd $PKGDIR
[[ -f $KIBANA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/kibana/$KIBANA -O $KIBANA
dpkg -i $KIBANA > /dev/null 2>&1

FILE=/etc/kibana/kibana.yml
grep "provisioned" $FILE || cat >> $FILE <<EOF
# provisioned
server.host: "0.0.0.0"
EOF

check_service kibana

# set up default index pattern
curl -ss -XPUT localhost:9200/.kibana/doc/index-pattern:a1571060-e8e2-11e7-9cf4-db76e233e72b -d @/vagrant/kibana-index-pattern.json -H'Content-Type: application/json'
curl -ss -XPUT localhost:9200/.kibana/doc/config:6.0.1 -d @/vagrant/kibana-index-pattern-config.json -H'Content-Type: application/json'

# logstash
echo "Provisioning LOGSTASH"
cd $PKGDIR
[[ -f $LOGSTASH ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/logstash/$LOGSTASH -O $LOGSTASH
dpkg -i $LOGSTASH > /dev/null 2>&1

FILE=/etc/logstash/conf.d/suricata.conf
[[ -f $FILE ]] || cat >> $FILE <<EOF
input {
  file {
    path => "/var/log/suricata/eve.json"
    tags => ["suricata"]
  }
}
filter {
  json {
    source => "message"
  }
  if 'syslog' not in [tags] {
    mutate { remove_field => [ "message", "Hostname" ] }
  }
}
output {
  elasticsearch {
    hosts => ["localhost"]
    index => "suricata-%{+YYYY.MM.dd.hh}"
  }
}
EOF
curl -ss -XPUT localhost:9200/_template/default -d @/vagrant/elastic-default-template.json -H'Content-Type: application/json'
chown root:logstash /var/log/suricata/eve.json
check_service logstash

# influx
echo "Provisioning INFLUXDB"
cd $PKGDIR
[[ -f $INFLUX ]] || wget $WGET_PARAMS https://dl.influxdata.com/influxdb/releases/$INFLUX -O $INFLUX
dpkg -i $INFLUX > /dev/null 2>&1
systemctl stop influxdb.service

check_service influxdb

# telegraf
echo "Provisioning TELEGRAF"
cd $PKGDIR
[[ -f $TELEGRAF ]] || wget $WGET_PARAMS https://dl.influxdata.com/telegraf/releases/$TELEGRAF -O $TELEGRAF
dpkg -i $TELEGRAF > /dev/null 2>&1

systemctl stop telegraf.service
grep "Amstelredamme" $FILE || cat > $FILE <<EOF
[global_tags]
  year = "2018"

[agent]
  hostname = "Amstelredamme"
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
