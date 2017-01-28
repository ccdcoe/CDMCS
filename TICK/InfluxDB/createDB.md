# Create database

```
# create database
curl -G http://localhost:8086/query --data-urlencode "q=CREATE DATABASE mydb"

# create retention policy
curl -G http://localhost:8086/query --data-urlencode "q=CREATE RETENTION POLICY myrp ON mydb DURATION 365d REPLICATION 1 DEFAULT"

# write data
curl -X POST http://localhost:8086/write --data-urlencode "db=mydb" --data-binary "cpu,region=useast,host=server_1,service=redis value=61"

# Query the Measurement
curl -G http://localhost:8086/query  --data-urlencode 'db=mydb' --data-urlencode 'q=SELECT * from cpu'
```

-----

-> Next []()
