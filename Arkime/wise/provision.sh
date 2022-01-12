PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"

DOCKER_ELA="docker.elastic.co/elasticsearch/elasticsearch-oss:6.7.1"
MOLOCH="moloch_1.8.0-1_amd64.deb"
USER="vagrant"

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

echo "Installing prerequisite packages..."
apt-get update && apt-get -y install jq wget curl pcregrep python-minimal python-pip python3-pip python-yaml libpcre3-dev libyaml-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev libsnappy-dev numactl >> /vagrant/provision.log 2>&1

docker network ls | grep cdmcs >/dev/null || docker network create -d bridge cdmcs

docker ps -a | grep elastic || docker run -dit --name elastic -h elastic --network cdmcs -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" --restart unless-stopped -p 9200:9200 $DOCKER_ELA 
sleep 10

check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive|failed" && systemctl start $1.service
  systemctl status $1.service
}
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
      community-id: yes
      community-id-seed: 0
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

echo "Configuring interfaces"
for iface in ${ifaces//;/ }; do
  echo "Setting capture params for $iface"
  for i in rx tx tso gso gro tx nocache copy sg rxvlan; do ethtool -K $iface $i off > /dev/null 2>&1; done
done

echo "Configuring moloch"
delim=";"; ifaces=""; for item in `ls /sys/class/net/ | egrep '^eth|ens|eno|enp'`; do ifaces+="$item$delim"; done ; ifaces=${ifaces%"$deli$delim"}
cd /data/moloch/etc
FILE=/data/moloch/etc/config.ini
[[ -f config.ini ]] || cp config.ini.sample $FILE
sed -i "s,MOLOCH_ELASTICSEARCH,localhost:9200,g"  config.ini
sed -i "s,MOLOCH_INTERFACE,$ifaces,g"             config.ini
sed -i "s,MOLOCH_INSTALL_DIR,/data/moloch,g"      config.ini
sed -i "s,MOLOCH_PASSWORD,test123,g"              config.ini

echo "Configuring databases"
cd /data/moloch/db
if [[ `./db.pl localhost:9200 info | grep "DB Version" | cut -d ":" -f2 | tr -d " "` -eq -1 ]]; then
  echo "INIT" | ./db.pl localhost:9200 init
fi

cd /data/moloch/bin
./moloch_update_geo.sh > /dev/null 2>&1
chown nobody:daemon /data/moloch/raw

echo "Adding viewer user"
cd /data/moloch/viewer && ../bin/node addUser.js vagrant vagrant vagrant --admin

echo "Configuring system limits"
ulimit -l unlimited
grep memlock /etc/security/limits.conf || echo "nofile 128000 - memlock unlimited" >> /etc/security/limits.conf
mkdir /data/moloch/raw && chown nobody:daemon /data/moloch/raw

echo "Configuring systemd services"

FILE=/etc/systemd/system/moloch-viewer.service
grep "moloch-viewer" $FILE || cat > $FILE <<EOF
[Unit]
Description=Moloch Viewer
After=network.target

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
After=network.target moloch-viewer.service

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
for service in viewer capture ; do
  systemctl enable moloch-$service.service
  systemctl start moloch-$service.service
  systemctl status moloch-$service.service
done

echo "making some noise"
while : ; do curl -s https://www.facebook.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s https://sysadminnid.tumblr.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s http://testmyids.com > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do curl -s -k https://self-signed.badssl.com/ > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do dig NS berylia.org @1.1.1.1 > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
while : ; do dig NS berylia.org @8.8.8.8 > /dev/null 2>&1 ; sleep $(shuf -i 15-60 -n 1); done &
