# Telegraf OUTPUT PLUGINS

## Before output

### Precision

By default, precision will be set to the same timestamp order as the
collection interval, with the maximum being 1s.
Precision will NOT be used for service inputs, such as *logparser* and statsd.
Valid values are "ns", "us" (or "µs"), "ms", "s".

```
 precision = ""
```

### Flushing interval

Default flushing interval for all outputs. You shouldn't set this below interval. Maximum flush_interval will be flush_interval + flush_jitter

```
 flush_interval = "10s"
```

### Flushing jitter

 Jitter the flush interval by a random amount. This is primarily to avoid
 large write spikes for users running a large number of telegraf instances.
 ie, a jitter of 5s and interval 10s means flushes will happen every 10-15s

 ```
 flush_jitter = "3s"
 ```


## Output plugins


Telegraf is able to serialize metrics into the following output data formats:
* InfluxDB Line Protocol
* JSON
* Graphite

Telegraf metrics, like InfluxDB points, are a combination of four basic parts:
* Measurement Name
* Tags
* Fields
* Timestamp

see https://github.com/influxdata/telegraf/blob/master/docs/DATA_FORMATS_OUTPUT.md


### Testing ..

```
[[outputs.file]]
  ## Files to write to, "stdout" is a specially handled file.
  files = ["stdout", "/tmp/metrics.out"]

  ## Data format to output.
  ## https://github.com/influxdata/telegraf/blob/master/docs/DATA_FORMATS_OUTPUT.md
  data_format = "json"

```

## InfluxDB

```
# Configuration for influxdb server to send metrics to
[[outputs.influxdb]]
  ## The full HTTP or UDP endpoint URL for your InfluxDB instance.
  ## Multiple urls can be specified as part of the same cluster,
  ## this means that only ONE of the urls will be written to each interval.
  # urls = ["udp://localhost:8089"] # UDP endpoint example
  urls = ["http://localhost:8086"] # required
  ## The target database for metrics (telegraf will create it if not exists).
  database = "telegraf" # required

  ## Retention policy to write to. Empty string writes to the default rp.
  retention_policy = ""
  ## Write consistency (clusters only), can be: "any", "one", "quorum", "all"
  write_consistency = "any"

  ## Write timeout (for the InfluxDB client), formatted as a string.
  ## If not provided, will default to 5s. 0s means no timeout (not recommended).
  timeout = "5s"
  # username = "telegraf"
  # password = "metricsmetricsmetricsmetrics"
  ## Set the user agent for HTTP POSTs (can be useful for log differentiation)
  # user_agent = "telegraf"
  ## Set UDP payload size, defaults to InfluxDB UDP Client default (512 bytes)
  # udp_payload = 512

  ## Optional SSL Config
  # ssl_ca = "/etc/telegraf/ca.pem"
  # ssl_cert = "/etc/telegraf/cert.pem"
  # ssl_key = "/etc/telegraf/key.pem"
  ## Use SSL but skip chain & host verification
  # insecure_skip_verify = false

```

## more outputs

see https://github.com/influxdata/telegraf/tree/master/plugins/outputs

------
-> Next [Inputs](inputs.md)
