SALTMASTER=$1
SALTMINIONID=$2
INFLUXDB=$3
[[ -z $3 ]] &&  INFLUXDB=$SALTMASTER

echo "LC_ALL=en_US.UTF-8" >> /etc/environment
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

echo "$(date) installing salt-minion host: $(hostname) salt-minion-id: $SALTMINIONID salt-master: $SALTMASTER"
service salt-minion stop > /dev/null 2>&1
echo "master: $SALTMASTER" > /etc/salt/minion
echo "id: $SALTMINIONID" >> /etc/salt/minion
service salt-minion start > /dev/null 2>&1

echo "$(date) installing telegraf host: $(hostname) $SALTMINIONID influxdb: $INFLUXDB"
dpkg -i /vagrant/telegraf_1.2.1_amd64.deb > /dev/null 2>&1
service telegraf stop > /dev/null 2>&1
sed -i -e 's,"http://localhost:8086"],"http://'${INFLUXDB}':8086"],g' /etc/telegraf/telegraf.conf
service telegraf start > /dev/null 2>&1

# exit with error if salt minion service is not running
if [ $(service salt-minion status | grep running | wc -l) -ne 1 ];
then
  echo "$(date) ERROR, salt-minion install failed host: $(hostname) salt-minion-id: $SALTMINIONID"
   exit -1
fi
