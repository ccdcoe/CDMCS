# day 3

* groking
* writing udf's

----

# logs -> telegraf

The logparser plugin streams and parses the given logfiles.
It has the capability of parsing "grok" patterns.

see
* https://github.com/influxdata/telegraf/tree/master/plugins/inputs/logparser
* https://skillsmatter.com/skillscasts/9432-structured-logging-the-future-of-log-management

-> next [Grok](/TICK/Telegraf/grok.md)

# udf
A UDF is a custom script or binary that can communicate with Kapacitor do something what Kapacitor can not do.

see
* https://github.com/influxdata/kapacitor/blob/master/udf/agent/README.md
* https://docs.influxdata.com/kapacitor/v1.1//nodes/u_d_f_node

## Examples

 * https://github.com/markuskont/tickscripts/blob/master/udf_scripts/useless.py
 * https://gist.github.com/hillar/cc1d79d6424e66ab4d1eb1f0f5a28d0a
 * https://gist.github.com/hillar/17520201b4edf86035cc4370745a2f38
 * https://github.com/influxdata/kapacitor/tree/master/udf/agent
