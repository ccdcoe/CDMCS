# Data Source

Grafana supports many different storage backends, see http://docs.grafana.org/datasources/

click and grow ... http://docs.grafana.org/datasources/influxdb/#adding-the-data-source

or

```
curl -s -XPOST --user admin:admin 192.168.11.11:3000/api/datasources -H "Content-Type: application/json" -d '{
    "name": "telegraf",
    "type": "influxdb",
    "access": "proxy",
    "url": "http://localhost:8086",
    "database": "telegraf",
    "isDefault": true
}'

```

see http://docs.grafana.org/http_api/data_source/#create-data-source

-----

-> next [First Dashboard](newDashboard.md)
