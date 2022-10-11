# Clustered elasticsearch

Elastic config options are in `elasticsearch.yml`. It should be placed under `/etc/elasticsearch` if installed from deb or bound under `/usr/share/elasticsearch/config/elasticsearch.yml` if running from docker images. Also, make sure that each node is bound to distinct port on host if running from container.

```
touch $PWD/elasticsearch.yml
docker run \
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

HTTP listener can be configured separately.

```
http:
  host: 0.0.0.0
```

Older elastic version (before 7) simply required **some master-eligible** nodes to be listied for unicast ping. Nodes would then autonegotiate cluster settings after this ping is successful.

```
discovery:
  zen:
    ping:
      unicast:
        hosts:
        - 192.168.56.120
        - 192.168.56.82
        - 192.168.56.122
```

[Version 7 changed the syntax and added more fine-graining options.](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-discovery-hosts-providers.html) New syntax is `discovery.seed_hosts`. Note that port suffix corresponds to **binary transport** port, which defaults to `9300` (but can be changed).

```
discovery.seed_hosts:
   - 192.168.56.120:9300
   - 192.168.56.11 
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

## Shard allocation and cluster API

* https://www.elastic.co/guide/en/elasticsearch/reference/current/shard-allocation-filtering.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/disk-allocator.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-update-settings.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/shards-allocation.html
* https://gist.github.com/markuskont/734a9ec946bf40801494f14b368a0668

Suppose our elastic cluster is distributed across multiple racks or datacenters. We can define custom attributes for each node. For example, we could configure `node.attr.datacenter: $NAME` or `node.attr.rack_id: $NAME`. Note that both `datacenter` and `rack_id` are totally custom attributes added by us. We could also create attribute `purpose` with values `hot`, `cold`, `archive`, and configure all new indices to be created on `hot` nodes.

Then we can make our cluster aware of those settings (**only needs to be done once per cluster**).

```
curl -XPUT -ss -H'Content-Type: application/json' "localhost:9200/_cluster/settings" -d '{
  "transient" : {
      "cluster.routing.allocation.awareness.attributes": "datacenter"
  }
}'
```

Once done, our replicas should then be distributed over datacenters.
