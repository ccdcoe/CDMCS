# Indexing alert log

 Having alert or network log on disk may be nice, but that approach does not really scale. Hunting needs tools that scale and can aggregate vast amounts of data. Because suricata can produce. Nowadays, [elastic stack](https://www.elastic.co/products) is the go-to method for doing that. Most front-end tools simply rely on elastic aggregations.

 * [More on elasticsearch](/common/elastic/)

## Getting started with Elastic

Getting suricata alert data to elastic and exposing it where needed is surprisingly simple, but can cause a lot of confusion as many tools exist for doing it. Which to use depends on your particular needs. But keep in mind that Elastic search engine is the only core component you need. Everything else depends on you.

### First node

* https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html

Strictly speaking, Elasticsearch only needs Java as dependency. However, these days it's easier to use docker when deploying your first testing node. Firstly, make sure your deploy host has this kernel setting in place. Otherwise, elasticsearch will fail on startup

```
sysctl -w vm.max_map_count=262144
```

Then start the container in console. Note that `-d` flag can be used to daemonize it, but running it from dedicated console window has the benefit of exposing the logs. Very useful for initial debug.

```
docker run -ti --name my-first-elastic -p 9200:9200 -e "discovery.type=single-node" -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" -e "cluster.name=cdmcs" docker.elastic.co/elasticsearch/elasticsearch-oss:6.5.4
```
