# Kapacitor TICKscript

* https://docs.influxdata.com/kapacitor/v1.2/tick/

> Kapacitor uses a DSL named TICKscript. The DSL is used to **define the pipelines** for **processing** data in Kapacitor.

see https://github.com/influxdata/kapacitor/blob/master/tick/TICKscript.md

## Syntax

* https://docs.influxdata.com/kapacitor/v1.2/tick/syntax/

## Example

```
cat > /etc/kapacitor/ticks/udf_outliers.tick <<EOF
var period = 100s
var every = 10s
var outputDB = 'telegraf'
var outputRP = 'autogen'
var outputMeasurement = 'outliers'
stream
    |from()
        .database('telegraf')
        .retentionPolicy('autogen')
        .measurement('mem')
        .groupBy('host')
    |window()
        .period(period)
        .every(every)
    @outliers()
        .field('used_percent')
        .scale(1.5)
    |log()
    |influxDBOut()
        .create()
        .database(outputDB)
        .retentionPolicy(outputRP)
        .measurement(outputMeasurement)
EOF

cd /etc/kapacitor/ticks
kapacitor define outliers -tick udf_outliers.tick -type stream -dbrp telegraf.autogen
kapacitor enable  outliers

```
