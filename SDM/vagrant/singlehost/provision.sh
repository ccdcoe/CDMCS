check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive|failed" && systemctl start $1.service
  systemctl status $1.service
}

# params
DEBUG=true
EXPOSE=192.168.56.11
PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"
APT_PARAMS="-q -y"

# versions
ELA="elasticsearch-6.1.2.deb"
KIBANA="kibana-6.1.2-amd64.deb"
LOGSTASH="logstash-6.1.2.deb"
INFLUX="influxdb_1.4.2_amd64.deb"
TELEGRAF="telegraf_1.5.1-1_amd64.deb"
GRAFANA="grafana_4.6.3_amd64.deb"
GOLANG="go1.9.4.linux-amd64.tar.gz"
NODE_VER="v6.13.0"
KAFKA_VER="1.0.0"
ZOO_VER="3.4.11"

start=$(date)

# basic OS config
FILE=/etc/sysctl.conf
grep "disable_ipv6" $FILE || cat >> $FILE <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p

echo "Provisioning REDIS"
# no persistent storage, only use as mem cache
docker run -dit --restart unless-stopped -p 127.0.0.1:6379:6379 redis

FILE=/etc/apt/apt.conf.d/99force-ipv4
[[ -f $FILE ]] ||  echo 'Acquire::ForceIPv4 "true";' | sudo tee $FILE
export DEBIAN_FRONTEND=noninteractive
mkdir -p /vagrant/pkgs

# basic software
apt-get update > /dev/null && apt-get install $APT_PARAMS curl htop vim tmux build-essential > /dev/null

echo "Provisioning JAVA"
install_oracle_java() {
  echo "Installing oracle Java"
  echo 'oracle-java8-installer shared/accepted-oracle-license-v1-1 boolean true' | debconf-set-selections \
  && add-apt-repository ppa:webupd8team/java \
  && apt-get update > /dev/null \
  && apt-get -y install oracle-java8-installer > /dev/null
}
java -version || install_oracle_java
#apt-get install $APT_PARAMS openjdk-8-jre-headless

# kafka + zookeeper needs name resolution
grep SDM /etc/hosts || echo "192.168.56.11  SDM" >> /etc/hosts

echo "Provisioning Zookeeper"
cd $PKGDIR
[[ -f "zookeeper-$ZOO_VER.tar.gz" ]] || wget $WGET_PARAMS http://apache.is.co.za/zookeeper/zookeeper-$ZOO_VER/zookeeper-$ZOO_VER.tar.gz && tar -xzf zookeeper-$ZOO_VER.tar.gz -C /opt

echo "Provisioning KAFKA"
cd $PKGDIR 
[[ -f "kafka_2.11-$KAFKA_VER.tgz" ]] || wget $WGET_PARAMS http://www-eu.apache.org/dist/kafka/$KAFKA_VER/kafka_2.11-$KAFKA_VER.tgz && tar -xzf kafka_2.11-$KAFKA_VER.tgz -C /opt
/opt/kafka_2.11-$KAFKA_VER/bin/kafka-server-start.sh -daemon /opt/kafka_2.11-$KAFKA_VER/config/server.properties
mkdir -p /var/lib/zookeeper
cat > /opt/zookeeper-$ZOO_VER/conf/zoo.cfg <<EOL
tickTime=2000
dataDir=/var/lib/zookeeper
clientPort=2181
initLimit=5
syncLimit=2
server.1=SDM:2888:3888
EOL
echo 1 > /var/lib/zookeeper/myid
bash /opt/zookeeper-$ZOO_VER/bin/zkServer.sh start

/opt/kafka_2.11-$KAFKA_VER/bin/zookeeper-shell.sh SDM:2181 <<< "ls /brokers/ids"

# collect sample data
echo "Provisioning FPROBE"
apt-get $APT_PARAMS install build-essential fprobe tcpdump > /dev/null
systemctl stop fprobe.service

sed -i 's/eth0/enp0s3/g' /etc/default/fprobe
sed -i 's/555/9995/g' /etc/default/fprobe
check_service fprobe

echo "Provisioning NODEJS"
cd $PKGDIR && [[ -f "node-$NODE_VER-linux-x64.tar.gz" ]] || wget $WGET_PARAMS https://nodejs.org/dist/$NODE_VER/node-$NODE_VER-linux-x64.tar.gz

tar -xzf node-$NODE_VER-linux-x64.tar.gz -C /opt || exit 1
ln -sf /opt/node-$NODE_VER-linux-x64/bin/node /usr/bin/node
ln -sf /opt/node-$NODE_VER-linux-x64/bin/npm /usr/bin/npm

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

# set up default index pattern
sleep 5

# logstash
echo "Provisioning LOGSTASH"
cd $PKGDIR
[[ -f $LOGSTASH ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/logstash/$LOGSTASH -O $LOGSTASH
dpkg -s logstash || dpkg -i $LOGSTASH > /dev/null 2>&1

FILE=/etc/logstash/conf.d/cdmcs.conf
grep "CDMCS" $FILE || cat >> $FILE <<EOF
input {
  redis {
    data_type => "list"
    host => "127.0.0.1"
    port => 6379
    key  => "cdmcs"
    tags => ["cdmcs", "CDMCS", "fromredis"]
  }
  kafka {
    bootstrap_servers => "SDM:9092"
    topics => ['SDM']
    id => "SDM-logstash-consumer"
    group_id => "SDM-logstash-consumer"
    tags => ['SDM']
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
    index => "cdmcs-%{+YYYY.MM.dd.hh}"
  }
}
EOF

check_service logstash

echo "Provisioning RSYSLOG"
add-apt-repository ppa:adiscon/v8-stable
apt-get update
apt-get install rsyslog rsyslog-mmjsonparse rsyslog-elasticsearch -y
FILE=/etc/rsyslog.d/75-elastic.conf
grep "CDMCS" $FILE || cat >> $FILE <<'EOF'
# CDMCS
module(load="omelasticsearch")
module(load="mmjsonparse")

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

template(name="JSON" type="list") {
    property(name="$!all-json")
}

if $syslogtag contains 'suricata' and $msg startswith ' @cee:' then {

  action(type="mmjsonparse")

  if $parsesuccess == "OK" then action(
    type="omelasticsearch"
    template="JSON"
    server="127.0.0.1"
    serverport="9200"
    searchIndex="suricata-index"
    dynSearchIndex="on"
  )

}
EOF

systemctl stop rsyslog.service
rsyslogd -N 1 || exit 1
check_service rsyslogd

# influx
echo "Provisioning INFLUXDB"
cd $PKGDIR
[[ -f $INFLUX ]] || wget $WGET_PARAMS https://dl.influxdata.com/influxdb/releases/$INFLUX -O $INFLUX
dpkg -s influxdb || dpkg -i $INFLUX > /dev/null 2>&1
systemctl stop influxdb.service
check_service influxdb

# grafana
echo "Provisioning GRAFANA"
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

# telegraf
echo "Provisioning TELEGRAF"
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

netstat -anutp
