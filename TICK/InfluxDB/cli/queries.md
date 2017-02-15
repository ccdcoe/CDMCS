# InfluxDB Querying using the CLI


## Set the Database Context
```
> USE telegraf
```

## Show measurements
Issue a `SHOW MEASUREMENTS` query.

```
> SHOW MEASUREMENTS
name: measurements
name
----
cpu
disk
mem
processes
swap
system
```

## Show series 
Issue a `SHOW SERIES` query.

```
> SHOW SERIES
key
---
cpu,cpu=cpu-total,host=Michaels-MBP-2.class.lan
cpu,cpu=cpu0,host=Michaels-MBP-2.class.lan
cpu,cpu=cpu1,host=Michaels-MBP-2.class.lan
cpu,cpu=cpu2,host=Michaels-MBP-2.class.lan
cpu,cpu=cpu3,host=Michaels-MBP-2.class.lan
cpu,cpu=cpu4,host=Michaels-MBP-2.class.lan
cpu,cpu=cpu5,host=Michaels-MBP-2.class.lan
cpu,cpu=cpu6,host=Michaels-MBP-2.class.lan
cpu,cpu=cpu7,host=Michaels-MBP-2.class.lan
disk,fstype=devfs,host=Michaels-MBP-2.class.lan,path=/dev
disk,fstype=hfs,host=Michaels-MBP-2.class.lan,path=/
disk,fstype=hfs,host=Michaels-MBP-2.class.lan,path=/Volumes/VirtualBox
mem,host=Michaels-MBP-2.class.lan
processes,host=Michaels-MBP-2.class.lan
swap,host=Michaels-MBP-2.class.lan
system,host=Michaels-MBP-2.class.lan
```

## Show field key
Issue a `SHOW FIELD KEYS` query

```
> SHOW FIELD KEYS
name: cpu
fieldKey         fieldType
--------         ---------
usage_guest      float
usage_guest_nice float
usage_idle       float
usage_iowait     float
usage_irq        float
usage_nice       float
usage_softirq    float
usage_steal      float
usage_system     float
usage_user       float

name: disk
fieldKey     fieldType
--------     ---------
free         integer
inodes_free  integer
inodes_total integer
inodes_used  integer
total        integer
used         integer
used_percent float

name: mem
fieldKey          fieldType
--------          ---------
active            integer
available         integer
available_percent float
buffered          integer
cached            integer
free              integer
inactive          integer
total             integer
used              integer
used_percent      float

name: processes
fieldKey fieldType
-------- ---------
blocked  integer
idle     integer
running  integer
sleeping integer
stopped  integer
total    integer
unknown  integer
zombies  integer

name: swap
fieldKey     fieldType
--------     ---------
free         integer
in           integer
out          integer
total        integer
used         integer
used_percent float

name: system
fieldKey      fieldType
--------      ---------
load1         float
load15        float
load5         float
n_cpus        integer
n_users       integer
uptime        integer
uptime_format string
```

## Show tag keys
Issue a `SHOW TAG KEYS` query.

```
> SHOW TAG KEYS
name: cpu
tagKey
------
cpu
host

name: disk
tagKey
------
fstype
host
path

name: mem
tagKey
------
host

name: processes
tagKey
------
host

name: swap
tagKey
------
host

name: system
tagKey
------
host
```


## Basic Select

Examples

```
SELECT * FROM cpu
SELECT free FROM mem
SELECT x + y FROM vars
SELECT x,y FROM nums
```

Try Running

```
SELECT * FROM CPU LIMIT 5
```

## Select with `WHERE` clause
Examples

```
SELECT * FROM cpu WHERE busy > 50
SELECT free FROM mem WHERE host = 'server1'
SELECT x + y FROM vars WHERE some_tag = 'some_key'
SELECT x,y FROM nums WHERE domain =~ /.*/
```

Try running

```
SELECT * FROM cpu WHERE usage_system > 5 LIMIT 5
```

## Select with relative time
Examples

```
SELECT * FROM cpu WHERE time > now() - 1h
SELECT * FROM cpu WHERE time > now() - 10s
SELECT free FROM mem WHERE time > now() - 4d
SELECT x + y FROM vars WHERE time > now() - 10w
SELECT x,y FROM nums WHERE time > now() + 15m
```

Try Running

```
SELECT * FROM cpu where time > now() - 1m
```

## Select with absolute time

Examples

```
SELECT * FROM cpu WHERE time > '2015-08-18 23:00:01.232000000'
SELECT free FROM mem WHERE time < '2015-09-19'
SELECT x + y FROM vars WHERE time > '2015-08-18T23:00:01.232000000Z'
```

## Select with `GROUP BY`
Examples

```
SELECT * FROM cpu GROUP BY host
SELECT * FROM cpu GROUP BY *
SELECT free FROM mem WHERE time > now() - 4d GROUP BY location
```

Try Running

```
SELECT * FROM cpu GROUP BY cpu limit 2
```

Try Running

```
SELECT * FROM cpu GROUP BY * limit 2
```

## Select with a function
### Aggregators
* count()
* distinct()
* integral()
* mean()
* median()
* spread()
* sum()
* stddev()

Examples

```
SELECT count(value) FROM cpu
SELECT mean(free) FROM mem WHERE time > now() - 1h
SELECT sum(x) FROM vars WHERE x > 100
SELECT median(y) FROM nums WHERE domain = 'Z'
```

Try running

```
SELECT mean(usage_idle) FROM cpu WHERE time > now() - 1m
```

Try running

```
SELECT mean(*) FROM cpu  WHERE time > now() - 1m
```

Try running

```
SELECT mean(*) FROM cpu WHERE time > now() - 1m GROUP BY cpu
```

Try running

```
SELECT mean(*) FROM cpu WHERE time > now() - 1m GROUP BY *
```

Try running

```
SELECT count(free) FROM mem
```

### Group by `time`
Examples

```
SELECT max(busy) FROM cpu WHERE time > now() - 1h GROUP BY time(10m)
SELECT mean(free) FROM mem WHERE time > now() - 1d GROUP BY time(1h), host
```

Try running

```
SELECT mean(free) FROM mem WHERE time > now() - 10m GROUP BY time(1m)
```


### Selectors
* bottom()
* first()
* last()
* max()
* min()
* percentile()
* top()

Examples

```
SELECT percentile(busy,90) FROM cpu WHERE time > now() - 1h
SELECT bottom(water_level,10) FROM factory WHERE location = 'SF'
SELECT max(x) FROM vars
SELECT last(y) FROM nums WHERE domain = ‘Z'
```

Try running

```
SELECT max(usage_idle), host, cpu FROM cpu WHERE time > now() - 1m
```

```
SELECT mean(usage_idle), host, cpu FROM cpu WHERE time > now() - 1m
```
^^^ Gives you an error

Try running

```
SELECT min(*) FROM cpu  WHERE time > now() - 1m
```

Try running

```
SELECT bottom(usage_system,4) FROM cpu WHERE time > now() - 1m GROUP BY cpu
```

### Transformer
* derivative()
* non_negative_derivative()
* difference()
* moving_average()

Examples

```
SELECT derivative(mean(write_ops)) FROM disk WHERE time > now() - 10m GROUP BY time(10s)
SELECT non_negative_derivative(x) FROM vars
```

Try running

```
SELECT non_negative_derivative(max(bytes_sent), 10s) FROM netstat WHERE time > now() - 1m GROUP BY time(10s)
```

-----

-> Next [Continuous Queries and Retention Policies](cqrp.md)
