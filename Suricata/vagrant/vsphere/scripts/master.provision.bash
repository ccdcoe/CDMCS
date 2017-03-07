SALTMASTER=$1

#echo "LC_ALL=en_US.UTF-8" >> /etc/environment
#echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

echo "$(date) installing salt mastert host: $(hostname) salt-master: $SALTMASTER "
apt-get -y install salt-master  > /dev/null 2>&1
service salt-master stop > /dev/null 2>&1
mv /etc/salt/master /etc/salt/master.from_package
# just convenience for students, don do it in real life
echo "open_mode: true" > /etc/salt/master
echo "auto_accept: true" >> /etc/salt/master
service salt-master start > /dev/null 2>&1

echo "$(date) installing influxdb host: $(hostname) influxdb: $SALTMASTER "
dpkg -i /vagrant/influxdb_1.2.0_amd64.deb > /dev/null 2>&1
service influxdb stop > /dev/null 2>&1
sed -i -e 's,# bind-address = ":8086",bind-address = "'${SALTMASTER}':8086",g' /etc/influxdb/influxdb.conf
service influxdb start > /dev/null 2>&1

echo "$(date) installing chronograf host: $(hostname) influxdb: $SALTMASTER "
dpkg -i /vagrant/chronograf_1.2.0~beta3_amd64.deb > /dev/null 2>&1
service chronograf start > /dev/null 2>&1

# grafana
echo "$(date) installing grafana host: $(hostname) influxdb: $SALTMASTER"
apt-get -y install libfontconfig > /dev/null 2>&1
dpkg -i /vagrant/grafana_4.1.2-1486989747_amd64.deb > /dev/null 2>&1
systemctl enable grafana-server > /dev/null 2>&1
systemctl start grafana-server
sleep 1
curl -s -XPOST --user admin:admin SALTMASTER:3000/api/datasources -H "Content-Type: application/json" -d '{
    "name": "telegraf",
    "type": "influxdb",
    "access": "proxy",
    "url": "http://localhost:8086",
    "database": "telegraf",
    "isDefault": true
}'

# exit with error if salt master service is not running
if [ $(service salt-master status | grep running | wc -l) -ne 1 ];
then
  echo "$(date) ERROR, salt-mster install failed host: $(hostname) salt-master: $SALTMASTER"
   exit -1
fi
