# Kapacitor TICKscript

* https://docs.influxdata.com/kapacitor/v1.2/tick/

> Kapacitor uses a DSL named TICKscript. The DSL is used to **define the pipelines** for **processing** data in Kapacitor.

see https://github.com/influxdata/kapacitor/blob/master/tick/TICKscript.md

## Syntax

* https://docs.influxdata.com/kapacitor/v1.2/tick/syntax/

## TICKscript Example

### Stream Script


**cpu_alert.tick**

```
stream
    // Select just the cpu measurement from our example database.
    |from()
        .measurement('cpu')
    |alert()
        .crit(lambda: "usage_idle" <  70)
	.warn(lambda: "usage_idle" < 80)
	.info(lambda: "usage_idle" < 98)
        // Whenever we get an alert write it to a file.
        .log('/tmp/alerts.log')
```

To add that script and create the task

```
kapacitor define cpu_alert \
	-type stream \
	-tick cpu_alert.tick
	-dbrp telegraf.autogen

```

To list the tasks

```
kapacitor list tasks
```

```
kapacitor list tasks
ID                                                 Type      Status    Executing Databases and Retention Policies
cpu_alert                                           stream    disabled  false     ["telegraf"."autogen"]
```

To show the task

```
kapacitor show cpu_alert
```

```
ID: cpu_alert
Error:
Template:
Type: stream
Status: disabled
Executing: false
Created: 14 Feb 17 05:35 EET
Modified: 14 Feb 17 05:35 EET
LastEnabled: 01 Jan 01 00:00 UTC
Databases Retention Policies: ["telegraf"."autogen"]
TICKscript:
stream
    // Select just the cpu measurement from our example database.
    |from()
        .measurement('cpu')
    |alert()
        .crit(lambda: "usage_idle" < 70)
        // Whenever we get an alert write it to a file.
        .log('/tmp/alerts.log')

DOT:
digraph cpu_alert {
stream0 -> from1;
from1 -> alert2;
}
```

To enable the task

```
kapacitor enable cpu_alert
```

Then show the task again

```
kapacitor show cpu_alert
```
```
ID: cpu_alert
Error:
Template:
Type: stream
Status: enabled
Executing: true
Created: 14 Feb 17 05:35 EET
Modified: 14 Feb 17 05:36 EET
LastEnabled: 14 Feb 17 05:36 EET
Databases Retention Policies: ["telegraf"."autogen"]
TICKscript:
stream
    // Select just the cpu measurement from our example database.
    |from()
        .measurement('cpu')
    |alert()
        .crit(lambda: "usage_idle" < 70)
        // Whenever we get an alert write it to a file.
        .log('/tmp/alerts.log')

DOT:
digraph cpu_alert {
graph [throughput="0.00 points/s"];

stream0 [avg_exec_time_ns="0s" ];
stream0 -> from1 [processed="0"];

from1 [avg_exec_time_ns="0s" ];
from1 -> alert2 [processed="0"];

alert2 [alerts_triggered="0" avg_exec_time_ns="0s" crits_triggered="0" infos_triggered="0" oks_triggered="0" warns_triggered="0" ];
}
```


## Real Example

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

see https://docs.influxdata.com/kapacitor/v1.2/examples/anomaly_detection/

## Exercise

### 1. Create tasks for the TICKscripts in the `scripts` folder.
Read over each of the TICKscripts in the `scripts` folder and create a task for each one.
### 2. Use Chronograf to create a basic alert in Kapacitor
In Kapacitor UI in Chronograf, build a basic alert for when the `free` fields in the `mem` measurement in the `telegraf` goes below `1G`, for each host.
### 3. Explore the Kapacitor documentation
Go to [kapacitor documentation](https://docs.influxdata.com/kapacitor/v1.2/nodes/) to learn about the various node types.

What services can you use to make alerts?

----
-> Next [Kapacitor CLI](cli.md)
