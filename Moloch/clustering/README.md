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

## Remote elasticsearch

Configuring moloch capture and viewer to use a remote elasticsearch (cluster) is quite straightforward, simply point them to correct ip-port combination.

```
elasticsearch=192.168.10.14:9200
```

Suppose we have multiple elastic proxies. Those can be delimited via semicolon. Just make sure they all belong to the same cluster.

```
elasticsearch=192.168.10.14:9200;192.168.10.36:9200
```

## moloch workers

Moloch is actually designed for clustering from the ground up. Pointing a new viewer node to existing elasticsearch cluster will already allow you to see all indexed sessions. However, opening an indexed session will likely fail. That's because viewer reads pcap data from disk, and also allows remote viewers to connetct to itsef. In other words, each viewer also acts as proxy for remote viewers. This behaviour can be observed locally as well. Suppose we would like to override the `--host` flag of our capture that would otherwise default to `hostname -f`.

```
./moloch-capture -c ../etc/config.ini --host some-host-123
```

Attempting to open a session that corresponds to query `node == some-host-123` will show you all of the SPI data, but payload will simply error.

```
Error talking to node 'some-host-123' using host 'some-host-123:8005' check viewer logs on 'host'
```

That is due to name resolution. Simply hack it with local resolver to get it working. We should add this to `/etc/hosts` of all viewer boxes.

```
192.168.10.14   some-host-123
```

And also inform our viewer of her new name.

```
../bin/node viewer.js -c ../etc/config.ini --host some-host-123
```

You should then be able to open the session as before.

## Tasks

## Parliament
