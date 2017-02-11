# Backup and restore

* https://docs.influxdata.com/influxdb/v1.2/tools/influx_inspect
* https://docs.influxdata.com/influxdb/v1.2/tools/shell/#influx-arguments

## Export
```
influx_inspect export \
  -database telegraf \
  -out /var/lib/influxdb/dump \
  -datadir /var/lib/influxdb/data/ \
  -waldir /var/lib/influxdb/wal/ \
  -start '2017-02-06T00:00:00.000000000Z' \
  -end '2017-02-10T23:59:59.000000000Z' \
  --compress
```
## Import
```
influx -import -path=/var/lib/influxdb/dump -precision=s
```
