# Telegraf INPUT PLUGINS

## Before input

### Collection interval

Default data collection interval for all inputs
```
interval = "10s"
```

Rounds collection interval to 'interval'
ie, if interval="10s" then always collect on :00, :10, :20, etc.
```
round_interval = true
```

### Collection jitter
Collection jitter is used to jitter the collection by a random amount.
Each plugin will sleep for a random time within jitter before collecting.
This can be used to avoid many *plugins querying things like sysfs* at the
same time, which can have a measurable effect on the system.

```
 collection_jitter = "0s"

```

### Default inputs

```
student:TICK hillar$ curl -s -4 https://raw.githubusercontent.com/influxdata/telegraf/master/etc/telegraf.conf | grep "^\[\[input"
[[inputs.cpu]]
[[inputs.disk]]
[[inputs.diskio]]
[[inputs.kernel]]
[[inputs.mem]]
[[inputs.processes]]
[[inputs.swap]]
[[inputs.system]]

```


## Input Plugins

* View usage instructions for each input by running `telegraf -usage <input-name>`.
* list of available plugins https://github.com/influxdata/telegraf/tree/master/plugins/inputs





https://docs.influxdata.com/telegraf/v1.2/inputs/
https://docs.influxdata.com/telegraf/v1.2/services/

https://docs.influxdata.com/telegraf/v1.2/concepts/data_formats_input/
