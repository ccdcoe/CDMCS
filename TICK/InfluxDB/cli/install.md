# Installing InfluxDB CLI on Debian | Ubuntu

If you already have the InfluxDB package installed. You can skip these steps.

## dpkg

* https://docs.influxdata.com/influxdb/v1.2/introduction/installation/

```
wget  -q -4 https://dl.influxdata.com/influxdb/releases/influxdb_1.2.0_amd64.deb
dpkg -i $INFLUXDB
service influxdb start

```

## Verify that CLI is installed
By running the command `influx` at the command line, you should be taken into a prompt.

```
$ influx
Connected to http://localhost:8086 version unknown
InfluxDB shell version: unknown
>
```

------
-> Next [Using CLI](createDB.md)
