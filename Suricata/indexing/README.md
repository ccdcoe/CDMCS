# Indexing alert log

Having alert or network log on disk may be nice, but that approach does not really scale. Hunting needs tools that scale and can aggregate vast amounts of data. Because suricata can produce. Nowadays, [elastic stack](https://www.elastic.co/products) is the go-to method for doing that. Most front-end tools simply rely on elastic aggregations.

## Getting started with elastic

Getting suricata alert data to elastic and exposing it where needed is surprisingly simple, but can cause a lot of confusion as many tools exist for doing it.  Which to use depends on your particular needs. But keep in mind that Elastic search engine is the only core component you need. Everything else depends on you.

### First node

* https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html

Strictly speaking, Elasticsearch only needs Java as dependency. However, these days it's easier to use docker when deploying your first testing node. Firstly, make sure your deploy host has this kernel setting in place. Otherwise, elasticsearch will fail on startup.

```
sysctl -w vm.max_map_count=262144
```

Then start the container in console. Note that `-d` flag can be used to daemonize it, but running it from dedicated console window has the benefit of exposing the logs. Very useful for initial debug.

```
docker run -ti --name my-first-elastic -p 9200:9200 -e "discovery.type=single-node" -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" -e "cluster.name=cdmcs" docker.elastic.co/elasticsearch/elasticsearch-oss:6.5.4
```

Then verify connectivity via `cat` api. Substitute `localhost` with box private IP if checking from host.

```
curl localhost:9200/_cat/indices
curl localhost:9200/_cat/nodes
curl localhost:9200/_cat/shards
curl localhost:9200/_cat/health
```

Note that indices and shards should return empty results, as we have no data yet.

### Documents and mappings

Manually insert a first testing document into index `first` with id `AAAA` and type `doc`.

```
curl -XPOST localhost:9200/first/doc/AAAA -H "Content-Type: application/json" -d '{"timestamp":"2019-01-22T11:18:13.156816+0000","flow_id":738588278199041,"in_iface":"enp0s3","event_type":"tls","src_ip":"10.0.2.15","src_port":42756,"dest_ip":"31.13.72.36","dest_port":443,"proto":"TCP","tls":{"subject":"C=US, ST=California, L=Menlo Park, O=Facebook, Inc., CN=*.facebook.com","issuerdn":"C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA","serial":"0B:3C:3B:60:1A:18:F5:9E:E2:B6:BB:05:60:5E:F2:C0","fingerprint":"bd:25:8c:1f:62:a4:a6:d9:cf:7d:98:12:d2:2e:2f:f5:7e:84:fb:36","sni":"www.facebook.com","version":"TLS 1.2","notbefore":"2017-12-15T00:00:00","notafter":"2019-03-22T12:00:00","ja3":{"hash":"1fe4c7a3544eb27afec2adfb3a3dbf60","string":"771,49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-13172-16-22-23-13,29-23-25-24,0-1-2"}}}'
```

Then verify that document exists via HTTP GET.

```
curl -XGET localhost:9200/first/doc/AAAA
```

Also verify indices.

```
curl localhost:9200/_cat/indices
```

Note that cluster health is `YELLOW`. This is because each index is distributed into shards. Each shard can have `N >= 0` replicas, which default being 1. In other words, each shard can have a redundant copy that also serves increases search throughput as replicas are open for reading while main shard is busy with search task. However, replica cannot be assigned to the same host as primary, so new single-host setup is perpetually degraded. We can verify this when looking at `_cat/shards`.

```
curl localhost:9200/_cat/shards
```
```
first 1 p STARTED    0   261b 172.17.0.2 _rGSnmd
first 1 r UNASSIGNED
first 2 p STARTED    0   261b 172.17.0.2 _rGSnmd
first 2 r UNASSIGNED
first 3 p STARTED    1 15.3kb 172.17.0.2 _rGSnmd
first 3 r UNASSIGNED
first 4 p STARTED    1 15.4kb 172.17.0.2 _rGSnmd
first 4 r UNASSIGNED
first 0 p STARTED    0   261b 172.17.0.2 _rGSnmd
first 0 r UNASSIGNED
```

This can be fixed by altering index settings.

```
curl -XGET 192.168.10.14:9200/first/_settings
```
```
{"first":{"settings":{"index":{"creation_date":"1548158688125","number_of_shards":"5","number_of_replicas":"1","uuid":"dKmyapUCTSWaGunmnybU9A","version":{"created":"6050499"},"provided_name":"first"}}}}
```
```
curl -XPUT 192.168.10.14:9200/first/_settings -H 'Content-Type: application/json' -d '{"settings":{"index":{"number_of_replicas":"0"}}}'
```

Note that number of shards cannot be changed once index is already created. Nor can individual [field mappings](https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html) be changed after creation.

```
curl "192.168.10.14:9200/first/_mappings" | jq .
```

Proper method to handle this issue is to [create a template](https://github.com/ccdcoe/CDMCS/blob/master/Suricata/vagrant/singlehost/provision.sh#L332). Note that `order` and `index-patterns` allows [overriding configuration values based on index name, and each field can be mapped into multiple types](https://github.com/ccdcoe/CDMCS/blob/master/Suricata/vagrant/singlehost/provision.sh#L384). Usually a string field that is mapped as `text` has a mapping with suffix `.keyword` that has a type `keyword`. You can delete an index if you messed up like this:

```
curl -XDELETE localhost:9200/first
```

You can also delete by wildcard.

```
curl -XDELETE "localhost:9200/*"
```

Finally, elastic is not meant for document storage or retreival. Keep your golden storage somewhere else, elastic is for `_search` and [data aggregations](https://github.com/ccdcoe/CDMCS/blob/master/Suricata/vagrant/singlehost/provision.sh#L845)

## Playing with python

Make sure that notebook is running. As `vagrant` user in `indexing` box, run the following command.

```
jupyter lab --ip=192.168.10.14
```

Alternatively, use a regular notebook as `jupyterlab` is quite new and may have issues.

```
jupyter --ip=192.168.10.14
```

Note that `ip` is needed if running notebook inside a vagrant VM, and it should correspond to private address of box that is accessible from hypervisor. Then look for the following line in console output:

```
    To access the notebook, open this file in a browser:
        file:///run/user/1000/jupyter/nbserver-11679-open.html
    Or copy and paste one of these URLs:
        http://192.168.10.14:8888/?token=<TOKEN>
```

Then copy the URL into host machine browser. Local notebooks are accessible under `localbox` sync point. Go through attached jupyter notebooks.

 * [Playing with eve.json](001-load-eve.ipynb)
 * [Getting started with elasticsearch](002-elastic-intro.ipynb)

## Other methods

 * https://suricata.readthedocs.io/en/latest/output/index.html
 * [Evebox esimport](evebox.md)
 * [Logstash](logstash.md)
 * [logstash+redis](/common/elastic/logstash-redis-ela.conf)
 * [Ingest node](/common/elastic/elastic.ingest.md)
 * [Rsyslog](rsyslog.omelastic.md)
 * [Rsyslog+kafka](rsyslog.kafka.conf)

# Evebox
