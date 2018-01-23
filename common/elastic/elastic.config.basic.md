# basic configuration

## JVM heap size

 * rule of thumb is 50% available memory
 * not so important
 * https://www.elastic.co/guide/en/elasticsearch/guide/current/heap-sizing.html

```
vim /etc/elasticsearch/jvm.options
```

```
-Xms1g
-Xmx1g
```

## rename

 * not really needed but becomes important later for clustered setup

```
vim /etc/elasticsearch/elasticsearch.yml
```

```
cluster.name: CDMCS
node.name: babbysfirstelasticsearch
```

## data directory

 * default is fine, but example may be useful if you need to add disks to existing boxes
 * [though this was not so nice](https://www.elastic.co/blog/multi-data-path-bug-in-elasticsearch-5-3-0)
 * does not do striping!
 * you cannot allocate shards to specific disks!

```
mkdir -p /srv/elasticsearch/{0,1}
chown elasticsearch /srv/elasticsearch/{0,1}
```
```
path.data: /srv/elasticsearch/0,/srv/elasticsearch/1
```

## roles

 * all roles should be enabled on single node

```
http.enabled: true
http.host: 127.0.0.1

node.data: true
node.ingest: true
node.master: true
```

----

next -> [clustered setup](basic.md)
