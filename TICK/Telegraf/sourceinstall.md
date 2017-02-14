# Telegraf: Installing from source

* https://github.com/influxdata/telegraf#from-source

 * Install Go
 * Setup your GOPATH
 * Run go get github.com/influxdata/telegraf
 * Run cd $GOPATH/src/github.com/influxdata/telegraf
 * Run make (make prepare && make build)


By defaul configuration file is located at */etc/telegraf/telegraf.conf* or set with $TELEGRAF_CONFIG_PATH

By default Telegraf will:
* log to *syslog*
* sends metrics to *local InfluxDB* every 10 seconds
* uses database name *telegraf* 

------
-> Next [Configuration](conf.md)
