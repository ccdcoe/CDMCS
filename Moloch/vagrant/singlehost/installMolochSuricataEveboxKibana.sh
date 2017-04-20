#!/bin/bash
#
# run this script on your own risk.
#
# it will install and configure
# Moloch, Suricata, Evebox and ElasticSearch and maybe Kibana
#
# ! it will generate some traffic to raise alerts
#

if [ "$(id -u)" != "0" ]; then
   echo "ERROR - This script must be run as root" 1>&2
   exit 1
fi

start=$(date)

cat >> /etc/sysctl.conf <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p

echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4
export DEBIAN_FRONTEND=noninteractive

#set versions here
#MOLOCH="moloch-nightly_amd64.deb"
MOLOCH=moloch_0.18.1-1_amd64.deb
ELASTICSEARCH="elasticsearch-5.2.2.deb"
EVEBOX="evebox_0.6.1_amd64.deb"
EVEDIR=http://evebox.org/files/release/0.6.1
# Jason >  Its my intention to tag and release often
# http://evebox.org/files/development/evebox-latest-amd64.deb
# http://evebox.org/files/release/0.6.1/evebox_0.6.1_amd64.deb


THEPASSWORD="admin"

cd /vagrant/

echo "$(date) installing java"
add-apt-repository ppa:webupd8team/java >> /vagrant/provision.log 2>&1
apt-get update >> /vagrant/provision.log 2>&1
echo "oracle-java8-installer shared/accepted-oracle-license-v1-1 select true" | sudo debconf-set-selections
apt-get -y install oracle-java8-installer >> /vagrant/provision.log 2>&1

echo "$(date) installing Elasticsearch"
[[ -f $ELASTICSEARCH ]] || wget  -q -4 https://artifacts.elastic.co/downloads/elasticsearch/$ELASTICSEARCH
dpkg -i $ELASTICSEARCH >> /vagrant/provision.log 2>&1
sed -i -e 's,-Xms2g,-Xms256m,g' /etc/elasticsearch/jvm.options
sed -i -e 's,-Xmx2g,-Xmx256m,g' /etc/elasticsearch/jvm.options
systemctl enable elasticsearch >> /vagrant/provision.log 2>&1
systemctl start elasticsearch

#suricata
echo "$(date) installing Suricata"
add-apt-repository ppa:oisf/suricata-stable >> /vagrant/provision.log 2>&1
apt-get update >> /vagrant/provision.log 2>&1
apt-get -y install suricata >> /vagrant/provision.log 2>&1
systemctl stop suricata

#ls /sys/class/net | grep -v lo
# see http://pevma.blogspot.com.ee/2015/05/suricata-multiple-interface.html
cat >> /etc/suricata/suricata.yaml <<EOF
stats:
  enabled: no
outputs:
  - fast:
      enabled: no
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert:
            tagged-packets: no
            xff:
              enabled: no
af-packet:
  - interface: enp0s3
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: enp0s8
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: /etc/suricata/rules
sensor-name: moloch-singlehost
EOF
touch  /etc/suricata//threshold.config
#suricata -T -vvv
[[ $(suricata -T) ]] || exit -1
systemctl daemon-reload
systemctl enable suricata >> /vagrant/provision.log 2>&1
systemctl start suricata

# evebox
echo "$(date) installing GeoLite2"
[[ -f 'GeoLite2-City.mmdb.gz' ]] || wget -q  -4 http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
mkdir -p /usr/local/share/GeoIP
gunzip GeoLite2-City.mmdb.gz --stdout > /usr/local/share/GeoIP/GeoLite2-City.mmdb
echo "$(date) installing evebox"
[[ -f $EVEBOX ]] ||wget  -q -4 $EVEDIR/$EVEBOX -O $EVEBOX
dpkg -i $EVEBOX >> /vagrant/provision.log 2>&1

cat >/etc/default/evebox <<EOF
ELASTICSEARCH_URL="-e http://localhost:9200"
ELASTICSEARCH_INDEX="--index suricata"
SURICATA_EVE="--end /var/log/suricata/eve.json"
EOF
cat > /lib/systemd/system/evebox.service <<EOF
[Unit]
Description=EveBox Server
[Service]
ExecStart=/usr/bin/evebox \$ELASTICSEARCH_URL \$ELASTICSEARCH_INDEX \$CONFIG \$EVEBOX_OPTS
EnvironmentFile=-/etc/default/evebox
[Install]
WantedBy=multi-user.target
EOF
cat > /lib/systemd/system/evebox-esimport.service <<EOF
[Unit]
Description=EveBox-EsImport
[Service]
ExecStart=/usr/bin/evebox esimport \$ELASTICSEARCH_URL \$ELASTICSEARCH_INDEX \$SURICATA_EVE
EnvironmentFile=-/etc/default/evebox
[Install]
WantedBy=multi-user.target
EOF


systemctl enable evebox-esimport >> /vagrant/provision.log 2>&1
systemctl start evebox-esimport

systemctl enable evebox >> /vagrant/provision.log 2>&1
systemctl start evebox

echo "$(date) installing moloch"
apt-get -y install libwww-perl libjson-perl >> /vagrant/provision.log 2>&1
[[ -f $MOLOCH ]] || wget  -q -4 http://files.molo.ch/builds/ubuntu-16.04/$MOLOCH
confcmd=$(dpkg -i $MOLOCH | tail -1 | rev | cut -f1 -d" " | rev) >> /vagrant/provision.log 2>&1
echo "$confcmd"
echo -en "enp0s3;enp0s8;\nno\nhttp://localhost:9200\ns2spassword\n" | $confcmd >> /vagrant/provision.log 2>&1
# set up wise server
sed -i -e 's,#wiseHost=127.0.0.1,wiseHost=127.0.0.1\nplugins=wise.so\nviewerPlugins=wise.js\nwiseTcpTupleLookups=true\nwiseUdpTupleLookups=true\n,g' /data/moloch/etc/config.ini
MOLOCH_INSTALL_DIR="/data/moloch"
sed -e "s,MOLOCH_INSTALL_DIR,${MOLOCH_INSTALL_DIR},g" < $MOLOCH_INSTALL_DIR/etc/molochwise.systemd.service > /etc/systemd/system/molochwise.service
cp /data/moloch/wiseService/wiseService.ini.sample /data/moloch/etc/wise.ini
cat > /data/moloch/etc/wise.ini <<EOF
[suricata]
evBox=http://192.168.10.11:5636
fields=severity;category;signature;flow_id;_id
mustNotHaveTags=archived
EOF
cp /vagrant/source.suricata.js /data/moloch/wiseService/
systemctl enable molochwise.service
systemctl start molochwise.service

until curl -sS 'http://127.0.0.1:9200/_cluster/health?wait_for_status=yellow&timeout=5s' >> /vagrant/provision.log 2>&1
do
  sleep 1
done
echo -en "INIT" | /data/moloch/db/db.pl http://localhost:9200 init >> /vagrant/provision.log 2>&1
/data/moloch/bin/moloch_add_user.sh admin "Admin User" $THEPASSWORD --admin
systemctl enable molochviewer.service
systemctl start molochviewer.service
ethtool -K enp0s3 tx off sg off gro off gso off lro off tso off >> /vagrant/provision.log 2>&1
ethtool -K enp0s8 tx off sg off gro off gso off lro off tso off >> /vagrant/provision.log 2>&1
systemctl start molochcapture.service

echo "$(date) generating some alert traffic, your ISP may detect it and disconnect you"
sleep 1
curl -s www.testmyids.com >> /vagrant/provision.log 2>&1
curl  -s https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist | while read i; do curl -s -m 2 $i > /dev/null; done &
# and some more
apt-get -y install nmap >> /vagrant/provision.log 2>&1
grep -h -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" /etc/suricata/rules/*.rules | sort | uniq | grep -v "\.0$" |rev| sort| rev | head -1500 | tail| while read ip;
do
  nmap -p 22,80,443 --script=banner $ip > /dev/null &
  sleep 1
done

echo "DONE :: start $start end $(date)"
netstat -ntple
