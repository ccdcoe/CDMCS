# Installing InfluxDB on Debian | Ubuntu

## dpkg

* https://docs.influxdata.com/influxdb/v1.2/introduction/installation/

```
wget  -q -4 https://dl.influxdata.com/influxdb/releases/influxdb_1.2.0_amd64.deb
dpkg -i $INFLUXDB
service influxdb start

```

By defaul configuration file is located at /etc/influxdb/influxdb.conf

By default InfluxDB will:

* log to syslog
* listens on localhost port 8086

------
-> Next [Configuration](conf.md)
