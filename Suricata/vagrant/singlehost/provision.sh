# script params
# set versions here

# SURICATA="4.0.3"
DEBUG=true
PROXY=http://192.168.10.1:3128

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

# install suricata but check if already exists
# add-apt-repository assumes ubuntu
suricata -V || bash -c "add-apt-repository ppa:oisf/suricata-stable && apt-get update && apt-get install -y suricata && suricata -V"
if $debug ; then ip addr show; fi
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
if $debug ; then suricata -T -vvv; fi

systemctl daemon-reload
systemctl is-enabled suricata.service 2>/dev/null | grep disabled && systemctl enable suricata.service
systemctl status suricata.service | egrep  "inactive" && systemctl start suricata.service
if $debug ; then systemctl status suricata.service ; fi
