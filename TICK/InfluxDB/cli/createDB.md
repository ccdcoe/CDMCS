# InfluxDB Writing Data using the CLI
Before getting started make sure that you're using the InfluxDB CLI.

You should see something like this:

```
$ influx
Connected to http://localhost:8086 version unknown
InfluxDB shell version: unknown
>
```

## Create Database
To create a database with the CLI, simply type the command `CREATE DATABASE <db name>`.

```
> CREATE DATABASE newdb
```

## Set the Database Context
```
> USE newdb
```


## Verify Database was Created
To see that the database was created, issue a `SHOW DATABASES` command.

```
> SHOW DATABASES
name: databases
name
----
_internal
mydb
chronograf
telegraf
newdb
```

## Write Data
To write data issue an `insert` command like so:

```
> insert cpu,region=useast,host=server_1,service=redis value=61
> insert cpu,region=uswest,host=server_2,service=redis value=32
> insert cpu,region=euwest,host=server_3,service=redis value=95
> insert mem,region=useast,host=server_1,service=redis free=6
> insert mem,region=uswest,host=server_2,service=redis free=2
> insert mem,region=euwest,host=server_3,service=redis free=5
> insert disk,region=useast,host=server_1,service=redis used=6,free=78
> insert disk,region=uswest,host=server_2,service=redis used=20,free=10
> insert disk,region=euwest,host=server_3,service=redis used=10,free=100
```

If you want to copy and paste

```
insert cpu,region=useast,host=server_1,service=redis value=61
insert cpu,region=uswest,host=server_2,service=redis value=32
insert cpu,region=euwest,host=server_3,service=redis value=95
insert mem,region=useast,host=server_1,service=redis free=6
insert mem,region=uswest,host=server_2,service=redis free=2
insert mem,region=euwest,host=server_3,service=redis free=5
insert disk,region=useast,host=server_1,service=redis used=6,free=78
insert disk,region=uswest,host=server_2,service=redis used=20,free=10
insert disk,region=euwest,host=server_3,service=redis used=10,free=100
```


# Query with the CLI
Issue a basic `SELECT` query.

```
> SELECT * FROM cpu
name: cpu
time                host     region service value
----                ----     ------ ------- -----
1487132909973765249 server_1 useast redis   6
1487132919507419205 server_2 uswest redis   32
1487132926555473586 server_3 euwest redis   95
```

# Change Precision of timestamp
Issue a `PRECISION <value>` command.

## Precision `s`
```
> PRECISION s
> SELECT * FROM cpu
name: cpu
time       host     region service value
----       ----     ------ ------- -----
1487132909 server_1 useast redis   6
1487132919 server_2 uswest redis   32
1487132926 server_3 euwest redis   95
```

## Precision `rfc3339`
```
> PRECISION rfc3339
> SELECT * FROM cpu
name: cpu
time                           host     region service value
----                           ----     ------ ------- -----
2017-02-15T04:28:29.973765249Z server_1 useast redis   6
2017-02-15T04:28:39.507419205Z server_2 uswest redis   32
2017-02-15T04:28:46.555473586Z server_3 euwest redis   95
```

# Change the format of results
Use the `FORMAT <type>` command to change the format of the results.

## Format Pretty JSON
```
> format json
> pretty
Pretty print enabled
> SELECT * FROM cpu
{
    "results": [
        {
            "series": [
                {
                    "name": "cpu",
                    "columns": [
                        "time",
                        "host",
                        "region",
                        "service",
                        "value"
                    ],
                    "values": [
                        [
                            "2017-02-15T04:28:29.973765249Z",
                            "server_1",
                            "useast",
                            "redis",
                            6
                        ],
                        [
                            "2017-02-15T04:28:39.507419205Z",
                            "server_2",
                            "uswest",
                            "redis",
                            32
                        ],
                        [
                            "2017-02-15T04:28:46.555473586Z",
                            "server_3",
                            "euwest",
                            "redis",
                            95
                        ]
                    ]
                }
            ]
        }
    ]
}
```

## Format CSV
```
> format csv
> SELECT * FROM cpu
name,time,host,region,service,value
cpu,2017-02-15T04:28:29.973765249Z,server_1,useast,redis,6
cpu,2017-02-15T04:28:39.507419205Z,server_2,uswest,redis,32
cpu,2017-02-15T04:28:46.555473586Z,server_3,euwest,redis,95
```

## Format column
```
> format column
> SELECT * FROM cpu
name: cpu
time                           host     region service value
----                           ----     ------ ------- -----
2017-02-15T04:28:29.973765249Z server_1 useast redis   6
2017-02-15T04:28:39.507419205Z server_2 uswest redis   32
2017-02-15T04:28:46.555473586Z server_3 euwest redis   95
```

### Exercise 1
Issue a basic `SELECT` statement for each of the measurements `cpu`, `mem`, and `free`.

### Exercise 2
Issue a `SHOW MEASUREMENTS` query.

### Exercise 3
Issue a `SHOW SERIES` query.

### Exercise 4
Issue a `SHOW FIELD KEYS` query

### Exercise 5
Issue a `SHOW TAG KEYS` query


-----

-> Next [Queries](queries.md)
