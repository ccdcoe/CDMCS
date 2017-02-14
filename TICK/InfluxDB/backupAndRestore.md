# Backup and restore

* https://docs.influxdata.com/influxdb/v1.2/tools/influx_inspect
* https://docs.influxdata.com/influxdb/v1.2/tools/shell/#import-data-from-a-file-with-import
* https://docs.influxdata.com/influxdb/v1.2/administration/backup_and_restore/

There are two days to acheive a backup and restore. 

1. Use the `backup` and `restore` subcommands of the `influxd` command
2. Using the `export` subcommand of the `influx_inspect` tool and the `-import` flag on the InfluxDB CLI `influx`.

## Using `influxd backup` and `influxd restore`

```
influxd backup -h
```

```
Downloads a snapshot of a data node and saves it to disk.

Usage: influxd backup [flags] PATH

    -host <host:port>
            The host to connect to snapshot. Defaults to 127.0.0.1:8088.
    -database <name>
            The database to backup.
    -retention <name>
            Optional. The retention policy to backup.
    -shard <id>
            Optional. The shard id to backup. If specified, retention is required.
    -since <2015-12-24T08:12:23>
            Optional. Do an incremental backup since the passed in RFC3339
            formatted time.
```

### Backing up the entire instance

```
influxd backup /tmp/backup
```

### Backing up a single database
```
influxd backup -database mydb /tmp/backup
```

### Partial backup using `-since` flag
```
influxd backup -database mydb -since 2016-02-01T00:00:00Z /tmp/backup
```

### Backup remotely
```
influxd backup -database mydb -since 2016-02-01T00:00:00Z -host 127.0.0.1:8088 /tmp/backup
```

### Restore metastore
```
influxd restore -metadir /var/lib/influxdb/meta /tmp/backup
```

### Restore data
```
influxd restore -database mydb -datadir /var/lib/influxdb/data /tmp/backup
```

## Using `influx_inspect` `export` and `influx -import`

### Export
```
influx_inspect export \
  -database mydb \
  -out /var/lib/influxdb/dump \
  -datadir /var/lib/influxdb/data/ \
  -waldir /var/lib/influxdb/wal/ \
  -start '2017-02-06T00:00:00.000000000Z' \
  -end '2017-02-10T23:59:59.000000000Z' \
  --compress
```

### Import
```
influx -import -path=/var/lib/influxdb/dump -precision=s
```
