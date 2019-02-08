FILE=/etc/sysctl.conf
grep "disable_ipv6" $FILE || cat >> $FILE <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

grep "max_map_count" $FILE || cat >> $FILE <<EOF
vm.max_map_count = 262144
EOF

sysctl -p

FILE=/etc/apt/apt.conf.d/99force-ipv4
[[ -f $FILE ]] ||  echo 'Acquire::ForceIPv4 "true";' | sudo tee $FILE
export DEBIAN_FRONTEND=noninteractive

add-apt-repository ppa:oisf/suricata-stable > /dev/null 2>&1 \
&& apt-get update > /dev/null \
&& apt-get install -y suricata > /dev/null

systemctl stop suricata.service
systemctl disable suricata.service

echo "Adding detects for SURICATA"
FILE=/etc/suricata/cdmcs-detect.yaml
grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
af-packet:
  - interface: enp0s3
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: enp0s8
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: /vagrant
rule-files:
 -  custom.rules
sensor-name: CDMCS-rules
EOF

FILE=/etc/suricata/suricata.yaml
grep "cdmcs" $FILE || cat >> $FILE <<EOF
include: /etc/suricata/cdmcs-detect.yaml
EOF

systemctl stop suricata
systemctl disable suricata
pgrep Suricata || [[ -f /var/run/suricata.pid ]] && rm /var/run/suricata.pid

