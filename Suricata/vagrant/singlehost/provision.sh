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
WGET_PARAMS="-4"

# versions
ELA=6.1.1
#SURICATA=4.0.3

# basic OS config
start=$(date)

FILE=/etc/sysctl.conf
grep "disable_ipv6" $FILE || cat >> $FILE <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p

FILE=/etc/profile
grep "proxy" $FILE || cat >> $FILE <<EOF
http_proxy=$PROXY
https_proxy=$PROXY
export http_proxy
export https_proxy
EOF
source /etc/profile

FILE=/etc/apt/apt.conf.d/99force-ipv4
[[ -f $FILE ]] ||  echo 'Acquire::ForceIPv4 "true";' | sudo tee $FILE
export DEBIAN_FRONTEND=noninteractive
mkdir -p /vagrant/pkgs

# basic software
apt-get update > /dev/null && apt-get install curl htop vim tmux > /dev/null

# java
install_oracle_java() {
  echo 'oracle-java8-installer shared/accepted-oracle-license-v1-1 boolean true' | debconf-set-selections \
  && add-apt-repository ppa:webupd8team/java > /dev/null 2>&1 \
  && apt-get update > /dev/null \
  && DEBIAN_FRONTEND=noninteractive apt-get -y install oracle-java8-installer > /dev/null
}
echo "Provisioning JAVA"
java -version || install_oracle_java

# elastic
echo "Provisioning ELASTICSEARCH"
FILE=$PKGDIR/elasticsearch-$ELA.deb
SHA=$FILE.sha512
[[ -f $FILE ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ELA.deb -O $FILE
[[ -f $FILE.sha512 ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ELA.deb.sha512 -O $SHA
cd $PKGDIR && shasum -a 512 -c $SHA && dpkg -i $FILE

check_service elasticsearch

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
