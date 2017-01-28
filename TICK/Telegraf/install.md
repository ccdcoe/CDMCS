# Installing on Debian | Ubuntu

* https://docs.influxdata.com/telegraf/v1.2/introduction/installation/

```
wget  -q -4 https://dl.influxdata.com/telegraf/releases/telegraf_1.1.2_amd64.deb
dpkg -i telegraf_1.1.2_amd64.deb
service telegraf start

```

By defaul configuration file is located at */etc/telegraf/telegraf.conf*

By default Telegraf will:
* log to *syslog*
* sends metrics to *local InfluxDB* every 10 seconds

------
-> Next [Configuration](conf.md)
