check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive" && systemctl start $1.service
  systemctl status $1.service
}

# params
DEBUG=false
PROXY=http://192.168.10.1:3128
PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"

# versions
ELA="elasticsearch-6.1.1.deb"
KIBANA="kibana-6.1.1-amd64.deb"
LOGSTASH="logstash-6.1.1.deb"

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

# java
install_oracle_java() {
  echo "Installing oracle Java"
  echo 'oracle-java8-installer shared/accepted-oracle-license-v1-1 boolean true' | debconf-set-selections \
  && add-apt-repository ppa:webupd8team/java > /dev/null 2>&1 \
  && apt-get update > /dev/null \
  && DEBIAN_FRONTEND=noninteractive apt-get -y install oracle-java8-installer > /dev/null
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
    index => "suricata-logstash-%{YYYY.MM.dd.hh}"
  }
}
EOF
check_service logstash

# suricata
install_suricata_from_ppa(){
  add-apt-repository ppa:oisf/suricata-stable > /dev/null 2>&1 \
  && apt-get update > /dev/null \
  && apt-get install -y suricata > /dev/null
}
echo "Provisioning SURICATA"
suricata -V || install_suricata_from_ppa

if $DEBUG ; then ip addr show; fi
systemctl stop suricata
FILE=/etc/suricata/suricata.yaml
grep "Amstelredamme" $FILE || cat >> $FILE <<EOF
# Amstelredamme added by vagrant
af-packet:
  - interface: eth0
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: eth1
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: /etc/suricata/rules
#rule-files:
# - scirius.rules
sensor-name: suricata
EOF

touch  /etc/suricata/threshold.config
if $DEBUG ; then suricata -T -vvv; fi

check_service suricata
chown root:logstash /var/log/suricata/eve.json && systemctl restart logstash.service
