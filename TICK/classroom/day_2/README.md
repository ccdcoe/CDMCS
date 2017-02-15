# day 2

* cli

* TICKscript


-----

# db administration

InfluxDB’s command line interface (influx) is an interactive shell for the HTTP API.

see https://docs.influxdata.com/influxdb/v1.2/tools/shell/

* cli params
* create db
* retention
* downsampling 
* [backup & restore](TICK/InfluxDB/backupAndRestore.md)

# Go to here [CLI](TICK/InfluxDB/cli/README.md)


##  processing, monitoring, and alerting on time series data

for intro see https://en.wikipedia.org/wiki/Directed_acyclic_graph

see 
* https://docs.influxdata.com/kapacitor/v1.2//tick/
* https://docs.influxdata.com/kapacitor/v1.2/nodes/
* https://docs.influxdata.com/kapacitor/v1.2/tick/expr/

* from
* window
* where
* groupBy
* ...

-----

TODO :: move to kapa directory ?

**Kapacitor** is a data processing engine. It can process both stream and batch data.



 * https://github.com/influxdata/kapacitor
 * https://docs.influxdata.com/kapacitor/


 * Perform any transformation currently possible in InfluxQL.
 * Add custom user defined functions if InfluxQL is missing it.


 * Process streaming data
 * Process batch data


 * Store transformed data back in InfluxDB.
 * Alert on defined anomalies
  * Integrate with Alerta, Slack, HipChat, OpsGenie,  Sensu, PagerDuty, and more.
