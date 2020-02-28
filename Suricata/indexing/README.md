# Indexing alerts

This is a vast topic that requires interactive scripting. Therefore, the content is split between this readme and jupyter notebooks. Start a notebook by running `jupyter lab --ip=0.0.0.0` and explore the `.ipynb` files for scripting examples and tasks.

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
docker run \
  -ti \                                                     # Keep terminal open interactively
  --rm \                                                    # Remove container on docker stop / ctrl+c; you will lose all data unless you mounted a persistent volume
  --name my-first-elastic \                                 # Explicit container name, otherwise will be randomly chosen
  -p 9200:9200 \                                            # Forward host port 9200 to container port 9200
  -e "discovery.type=single-node" \                         # For single-node testing only,  dont use for cluster
  -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \                     # Minimal amount of Java heap to avoid running out of memory in Vagrant VM
  -e "cluster.name=cdmcs" \                                 # Cluster name, relevant for multihost clustered setup
    docker.elastic.co/elasticsearch/elasticsearch-oss:7.6.0 # Image source itself with version tag
```

Then verify connectivity via `cat` api. Substitute `localhost` with box private IP if checking from hypervisor host, or Vagrant public IP when checking from remote host.

```
curl localhost:9200/_cat/indices
curl localhost:9200/_cat/nodes
curl localhost:9200/_cat/shards
curl localhost:9200/_cat/health
```

Note that indices and shards should return empty results, as we have no data yet.

### Documents and mappings

Manually insert a first testing document into index `first` with id `AAAA` and type `_doc` (types are irrelevant post elastic 7, but keep using `_doc` to avoid issues).

```
curl -XPOST localhost:9200/first/_doc/AAAA -H "Content-Type: application/json" -d '{"timestamp":"2019-01-22T11:18:13.156816+0000","flow_id":738588278199041,"in_iface":"enp0s3","event_type":"tls","src_ip":"10.0.2.15","src_port":42756,"dest_ip":"31.13.72.36","dest_port":443,"proto":"TCP","tls":{"subject":"C=US, ST=California, L=Menlo Park, O=Facebook, Inc., CN=*.facebook.com","issuerdn":"C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA","serial":"0B:3C:3B:60:1A:18:F5:9E:E2:B6:BB:05:60:5E:F2:C0","fingerprint":"bd:25:8c:1f:62:a4:a6:d9:cf:7d:98:12:d2:2e:2f:f5:7e:84:fb:36","sni":"www.facebook.com","version":"TLS 1.2","notbefore":"2017-12-15T00:00:00","notafter":"2019-03-22T12:00:00","ja3":{"hash":"1fe4c7a3544eb27afec2adfb3a3dbf60","string":"771,49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-13172-16-22-23-13,29-23-25-24,0-1-2"}}}'
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

## Clustered elasticsearch

Elastic config options are in `elasticsearch.yml`. It should be placed under `/etc/elasticsearch` if installed from deb or bound under `/usr/share/elasticsearch/config/elasticsearch.yml` if running from docker images. Also, make sure that each node is bound to distinct port on host if running from container.

```
touch $PWD/elasticsearch.yml; docker run \
  -ti \
  --rm \
  -p 9200:9200 \
  -p 9300:9300 \
  -v $PWD/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml \
  -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \
    docker.elastic.co/elasticsearch/elasticsearch-oss:7.6.0
```

Firstly, all nodes should be configured to belong to common cluster.

```
cluster.name: josephine
```

Alternatively, any supported elastic config option can be passed to the VM via config variable.

```
docker run \
  -ti \
  --rm \
  -p 9200:9200 \
  -p 9300:9300 \
  -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \
  -e "cluster.name=josephine" \
    docker.elastic.co/elasticsearch/elasticsearch-oss:7.6.0
```

Each node can be configured for a variety of roles. Single node can fulfill many roles, though specialized workers are common in production.
 * `master` is responsible for coordinating other cluster nodes, or be in in standby mode in case main master fails;
 * `data` nodes store data on disk and function as indexing and search workers;
 * `ingest` nodes run pipeline jobs before indexing the data, and essentially function as logstash integrated into elastic;

```
node:
  name: firstnode
  data: false
  ingest: false
  master: false
```

Note that node name is arbitrary and simply has to be unique. It will be automatically generated if left unconfigured. There is another role that is not classified as such. Elastic uses binary connection for intra-cluster communication and HTTP for talking to the world. A common practice is to create specialized *no-data* or *proxy* nodes that are configured with all roles disabled and http enabled. Role of these nodes is simply to collect JSON bulks and to forward it to worker nodes over binary. Workers usually have http disabled or simply bound to localhost. **Please flush your container or data directory if you change node name. Otherwise artifacts from last run may conflict with new config.**

Binding elastic to specific interfaces can be a good idea if your box has multiple interfaces. Elasic is not terribly intelligent at picking the right interface automatically, and it can cause confusion.

```
network:
  host: 0.0.0.0
```

Docker nodes are located inside a docker private network, thus you need to use either a `--network host` flag when creating a container. This binds continer to host network stack and bypasses docker networking entirely. Do not do in production. Or you can alter the `network.publish_host` parameter from elasticsearch.

```
network:
  host: 0.0.0.0
  publish_host: ACCESSIBLE_IP_OR_ADDRESS
```

HTTP listener is configured separately.

```
http:
  enabled: true
  host: 0.0.0.0
```

Older elastic version (before 7) simply required **some master-eligible** nodes to be listied for unicast ping. Nodes would then autonegotiate cluster settings after this ping is successful.

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

[Version 7 changed the syntax and added more fine-graining options.](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-discovery-hosts-providers.html) New syntax is `discovery.seed_hosts`. Note that port suffix corresponds to **binary transport** port, which defaults to `9300` (but can be changed).

```
discovery.seed_hosts:
   - 192.168.10.120:9300
   - 192.168.10.11 
```

Furthermore, we now need to define an initial list of **master-eligible nodes** when bootstrapping a new cluster. Otherwise, you will be greeted by an error like this -

```
"message": "master not discovered yet, this node has not previously joined a bootstrapped (v7+) cluster, and [cluster.initial_master_nodes] is empty on this node
```

To fix this, you need a list of potential master **node names** (not network addresses) in configuration. In other words, names in this list must correspond to `node.name` value for each listed master node.

```
cluster.initial_master_nodes:
  - firstnode
  - secondnode
```

Then verify that nodes are listed with proper roles via `_cat` API.

```
curl PROXY:PORT/_cat/nodes
```

# Collecting events from Suricata

Suricata supports following outputs:
 * Flat file;
 * Syslog;
 * Unix socket;
 * Redis;

We will only cover Redis due to time limitations.

## redis

* https://redis.io/topics/quickstart

Redis is in-memory data structure store, commonly used as buffer or memory cache. It can be deployed by building it yourself or just running the docker container.

```
wget http://download.redis.io/redis-stable.tar.gz
tar xvzf redis-stable.tar.gz
cd redis-stable
make
apt-get install -y build-essential
make
make install
redis-server --help
redis-server
redis-server --bind 0.0.0.0 --daemonize yes
redis-cli
netstat -anutp | grep 6379
```

However, a simple thing to do is simply to run it through docker container.

```
docker run -it \
  --name redis \
    redis
```

### Suricata config

* make sure redis support is actually compiled in

```
filetype: redis #regular|syslog|unix_dgram|unix_stream|redis
redis:
  server: 127.0.0.1
  port: 6379
  async: true ## if redis replies are read asynchronously
  mode: list ## possible values: list|lpush (default), rpush, channel|publish
             ## lpush and rpush are using a Redis list. "list" is an alias for lpush
             ## publish is using a Redis channel. "channel" is an alias for publish
  key: suricata ## key or channel to use (default to suricata)
  pipelining:
    enabled: yes ## set enable to yes to enable query pipelining
    batch-size: 10 ## number of entry to keep in buffer
```

### Testing

```
redis-cli
127.0.0.1:6379> KEYS *
1) "suricata"
```

## Shippers

Bridging suricata and elastic is covered in attached notebooks. 

Many tools exist for shipping logs to elastic. However, we will not cover them due to schedule limitations. [Materials are covered here for archived reference](shippers.md)

---

[back](/Suricata)
