# Elasticsearch

* This section assumes that student is already familiar with Suricata, and is able to use it for producing alert and protocol JSON logs;

## Background

* Suricata index is not your typical database;
* Suricata produces vast amount of **highly dyncamic** JSON;
* Modeling it to traditional database schema is very difficult;
  * Even more difficult to maintain (EVE gets new fields and variations);
* Most database engines have trouble keeping up;
  * Super write heavy;
  * Heavy volume of data, requires horizontal scaling (that most free databases have trouble with);
  * Lot of heavy nested JSON;
  * Lot of string and (fuzzy) full text searches;
  * Dropping data not okay, you don't know what you need until you need it;
  * On that node, also needs flexible frontend as we don't know what we need and most web devs have trouble with this concept;
* So, everyone is using Elastic, *capisce*;
  * Horizontal scaling;
  * NoSQL, no DB schema (kinda, depending on how you view mappings);
  * Built around ingesting JSON;
  * Built to make full-text search scalable;
  * Kibana is very flexible frontend;
  * De-facto standard for logging nowadays, lot of security and threat hunting tooling;
* Not without its faults;
  * Too many fields;
  * Mapping pain;
  * Cluster funtime;
  * Java funtime;
  * ...
* But best we have (in open-source space);

## Getting started

* https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html

Strictly speaking, Elasticsearch only needs Java as dependency. However, Elastic is simply a supporting tool for Suricata in this course context. So, we will use **docker** to get Elastic up and running as fast as we can. Containers isolate application from parent OS and thus save us time on dependency setup and subsequent cleanup.

Nevertheless, container is still running on host. So, kernel parameters also need to be configured there. Elastic is very memory hungry, so it requires some tuning. Otherwise, **it may fail to start**.

```
sysctl -w vm.max_map_count=262144
```

Then start the container in console. Note that `-d` flag can be used to daemonize it, but running it from dedicated console window has the benefit of exposing the logs. Very useful for initial debug.

```
docker run -ti --rm --name my-first-elastic -p 9200:9200 -e "discovery.type=single-node" -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" -e "cluster.name=cdmcs" docker.elastic.co/elasticsearch/elasticsearch-oss:7.10.2
```

You should be able to `curl` against `localhost:9200`. **Substitute `localhost` with remote IP of the box you are testing on for remote setups**.

```
curl localhost:9200
```

Result should be something like this.

```
{
  "name" : "8fec3bcf91ce",
  "cluster_name" : "cdmcs",
  "cluster_uuid" : "aZJHLCt5SAmTIayUJ9bEJg",
  "version" : {
    "number" : "7.10.2",
    "build_flavor" : "oss",
    "build_type" : "docker",
    "build_hash" : "747e1cc71def077253878a59143c1f785afa92b9",
    "build_date" : "2021-01-13T00:42:12.435326Z",
    "build_snapshot" : false,
    "lucene_version" : "8.7.0",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
```

**If you don't, ask help from instructors**. Otherwise, proceed.

Then verify connectivity via `cat` API. It is useful for extracting all kind of metadata from Elasticsearch. Following endpoints are the most common ones used for high-level operations. Again, substitute `localhost` with appropriate IP if needed.

```
curl localhost:9200/_cat/indices
curl localhost:9200/_cat/nodes
curl localhost:9200/_cat/shards
curl localhost:9200/_cat/health
```

Keep those endpoints in mind. **You will need them later.** Fresh instance has no data and thus not indices nor shards. So, only endpoint that returns non-empty response should be `/_cat/health`.

## Documents and mappings

* As mentioned, Elastic is for storing arbitrary JSON.;
* Each JSON entry is a *document*;
* Each *document* is stored in *index*;
* Each *index* can be split into *shards*;
  * Those *shards* can be on different *nodes* (hosts) in clustered setup;
* Each *document* **had** a *type* (deprecated feature that never panned out and just caused confusion);

Individual documents can be inserted into Elastic with HTTP POST requests. Manually insert a first testing document into index `first` with id `AAAA` and type `_doc` (types are irrelevant post elastic 7, but keep using `_doc` to avoid issues).

```
curl -XPOST localhost:9200/first/_doc/AAAA -H "Content-Type: application/json" -d '{"timestamp":"2019-01-22T11:18:13.156816+0000","flow_id":738588278199041,"in_iface":"enp0s3","event_type":"tls","src_ip":"10.0.2.15","src_port":42756,"dest_ip":"31.13.72.36","dest_port":443,"proto":"TCP","tls":{"subject":"C=US, ST=California, L=Menlo Park, O=Facebook, Inc., CN=*.facebook.com","issuerdn":"C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA","serial":"0B:3C:3B:60:1A:18:F5:9E:E2:B6:BB:05:60:5E:F2:C0","fingerprint":"bd:25:8c:1f:62:a4:a6:d9:cf:7d:98:12:d2:2e:2f:f5:7e:84:fb:36","sni":"www.facebook.com","version":"TLS 1.2","notbefore":"2017-12-15T00:00:00","notafter":"2019-03-22T12:00:00","ja3":{"hash":"1fe4c7a3544eb27afec2adfb3a3dbf60","string":"771,49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-13172-16-22-23-13,29-23-25-24,0-1-2"}}}'
```

Individual documents can be extracted with HTTP GET.

```
curl -XGET localhost:9200/first/_doc/AAAA
```

Or search from from `_search` API.

```
curl -XGET localhost:9200/first/_search
```

Since we now have data, we should also be able to use `/_cat/indices` API.

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

Number of shards cannot be changed once index is already created. Nor can individual [field mappings](https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html) be changed after creation. However, number of replicas can be changed whenever needed. Just keep in mind it would invoke full cluster rebalance.

Mappings for individual fields can be observed per index via `_mappings` API.

```
curl "192.168.10.14:9200/first/_mappings" | jq .
```

Mapping persistence can be achieved using *templates*. But this is out of scope for now.

Finally, individual index can be deleted with HTTP DELETE command.

```
curl -XDELETE localhost:9200/first
```

You can also delete by wildcard.

```
curl -XDELETE "localhost:9200/*"
```
