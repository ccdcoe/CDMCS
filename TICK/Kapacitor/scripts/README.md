# Example TICKscripts
This includes two types of TICKscripts. Those that rely on Telegraf and those that rely on the `_internal` database.

## Use `_internal`

All of the examples from this section operate on `streams`.

* `loca_write_failures.tick`
* `record_series_count.tick`
* `record_throughput.tick`

### Example of enabling a task

```
kapacitor define local_write_failures local_write_failures.tick -dbrp _internal.monitor -type stream
kapacitor enable local_write_failures
```

## Use `telegraf`

### Batch
* `any_influxdb_write_errors.tick`
* `high_host_disk.tick`
* `high_host_mem.tick`

#### Example
```
kapacitor define high_host_disk high_host_disk.tick -dbrp telegraf.autogen -type batch
kapacitor enable high_host_disk
```

### Stream
* `system_down.tick`

#### Example

```
kapacitor define system_down system_down.tick -dbrp telegraf.autogen -type stream
kapacitor enable system_down
```
