# Elasticsearch config

```
cluster:
  name: josephine
discovery:
  zen:
    ping:
      unicast:
        hosts:
        - 192.168.10.120
        - 192.168.10.82
        - 192.168.10.122
http:
  enabled: true
  host: 0.0.0.0
network:
  host: 192.168.10.140
node:
  data: false
  ingest: false
  master: false
  name: es-proxy-0.labor.sise
path:
  data:
  - /srv/elasticsearch/0
  - /srv/elasticsearch/1
  logs: /var/log/elasticsearch
```
