# Clustering

  * https://github.com/aol/moloch/wiki/Architecture#multiple-hosts-monitoring-multiple-network-segments
  * https://github.com/aol/moloch/wiki/Architecture#multiple-hosts-monitoring-high-traffic-networks
  * https://github.com/aol/moloch/wiki/Architecture#multiple-hosts-monitoring-high-traffic-networks

## Clustered elasticsearch

Elastic config options are in `elasticsearch.yml`. It should be placed under `/etc/elasticsearch` if installed from deb or bound under `/usr/share/elasticsearch/config/elasticsearch.yml` if running from docker images. Also, make sure that each node is bound to distinct port on host if running from container.

```
docker run -ti -p 9200:9200 -p 9300:9300 -v $PWD/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" docker.elastic.co/elasticsearch/elasticsearch-oss:6.6.0
```

Firstly, all nodes should be configured to belong to common cluster.

```
cluster:
  name: josephine
```

Then, configure a list of eligible masters. It is only used for bootstraping initial connection. Any node that is eligible for master role can be elected master, not just the ones listed for initial ping.

```
discovery:
  zen:
    ping:
      unicast:
        hosts:
        - 192.168.10.120
        - 192.168.10.82
        - 192.168.10.122
```

Each node can be configured for a variety of roles. Single node can fulfill many roles, though specialized workers are common in production.
 * `master` is responsible for coordinating other cluster nodes, or be in in standby mode in case main master fails;
 * `data` nodes store data on disk and function as indexing and search workers;
 * `ingest` nodes run pipeline jobs before indexing the data, and essentially function as logstash integrated into elastic;

```
node:
  name: es-proxy-0.labor.sise
  data: false
  ingest: false
  master: false
```

Note that node dame is arbitrary and simply has to be unique. It will be automatically generated if left unconfigured. There is another role that is not classified as such. Elastic uses binary connection for intra-cluster communication and HTTP for talking to the world. A common practice is to create specialized *no-data* or *proxy* nodes that are configured with all roles disabled and http enabled. Role of these nodes is simply to collect JSON bulks and to forward it to worker nodes over binary. Workers usually have http disabled or simply bound to localhost.

```
http:
  enabled: true
  host: 0.0.0.0
```

Binding elastic to specific interfaces can be a good idea if your box has multiple interfaces. Elasic is not terribly intelligent at picking the right interface automatically, and it can cause confusion.

```
network:
  host: 0.0.0.0
```

Both data and log directories can be customized if needed. Multiple data directories can be defined, for example in systems with multiple disks. Note that elastic is not really designed for scaling much inside the host, so data directory is picked simply based on disk usage.

```
path:
  data:
  - /srv/elasticsearch/0
  - /srv/elasticsearch/1
  logs: /var/log/elasticsearch
```

Since we are doing pretty much everything in docker, it may be better to just mount correct docker volumes to default data and log directories.
