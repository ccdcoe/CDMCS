# InfluxDB Writing Data

## Create Database
To create a database issue a POST request to the `/query` endpoint with a query-string `q` that has the command `CREATE DATABASE <db name>`.

```
# create database
curl -s -XPOST http://localhost:8086/query --data-urlencode "q=CREATE DATABASE mydb" | jq
```

This returns

```
{
  "results": [
    {
      "statement_id": 0
    }
  ]
}
```

## Verify Database was Created
To see that the database was created, issue a GET request to the `/query` endpoint with query string `q` as `SHOW DATABASES`.

```
curl -s -G http://localhost:8086/query --data-urlencode "q=SHOW DATABASES" | jq
```

```
{
  "results": [
    {
      "statement_id": 0,
      "series": [
        {
          "name": "databases",
          "columns": [
            "name"
          ],
          "values": [
            [
              "_internal"
            ],
            [
              "mydb"
            ]
          ]
        }
      ]
    }
  ]
}
```

You'll see two databases `_internal` and `mydb`. The `_internal` database contains metrics about the InfluxDB instance. It is useful for debugging.

## Write Data
To write data you issue a POST request to the `/write` endpoint of the HTTP API. You must specify which database `db` that you'd like to write to and give a point or batch of points in line protocol.

```
curl -X POST http://localhost:8086/write?db=mydb --data-binary "cpu,region=useast,host=server_1,service=redis value=61"
```

```
curl -X POST http://localhost:8086/write?db=mydb --data-binary "cpu,region=uswest,host=server_2,service=redis value=32"
```

```
curl -X POST http://localhost:8086/write?db=mydb --data-binary "cpu,region=euwest,host=server_3,service=redis value=95"
```

# Query the Measurement
To query the data back issue a GET request to the `/query` endpoints. Specify both the `db=mydb` and `q=SELECT * FROM cpu` query parameters.

```
curl -s -G http://localhost:8086/query  --data-urlencode 'db=mydb' --data-urlencode 'q=SELECT * from cpu' | jq
```

```
{
  "results": [
    {
      "statement_id": 0,
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
              "2017-02-14T02:17:25.366982001Z",
              "server_1",
              "useast",
              "redis",
              61
            ],
            [
              "2017-02-14T02:17:32.601289607Z",
              "server_2",
              "uswest",
              "redis",
              32
            ],
            [
              "2017-02-14T02:17:39.479000375Z",
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

### Exercise 1
Write the following points into the database `mydb`

```
mem,region=useast,host=server_1,service=redis free=10
mem,region=uswest,host=server_2,service=redis free=9
mem,region=euwest,host=server_2,service=redis free=9.9
```

Can you write it as a single HTTP request?

### Exercise 2
Issue a `SHOW MEASUREMENTS` query to the `mydb` database.

### Exercise 3
Issue a `SHOW SERIES` query to the `mydb` database.



-----

-> Next [backup & restore](backupAndRestore.md)
