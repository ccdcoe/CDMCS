# Scalable indexing

Single-node setups only get you so far. At one point you have to scale out.

## Clustered elasticsearch

Elastic config options are in `elasticsearch.yml`. It should be placed under `/etc/elasticsearch` if installed from deb or bound under `/usr/share/elasticsearch/config/elasticsearch.yml` if running from docker images. Also, make sure that each node is bound to distinct port on host if running from container.

```
docker run -ti -p 9200:9200 -p 9300-9400:9300-9400 -v $PWD/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" docker.elastic.co/elasticsearch/elasticsearch-oss:6.6.0
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
  host: 192.168.10.140
```

Both data and log directories can be customized if needed. Multiple data directories can be defined, for example in systems with multiple disks. Note that elastic is not really designed for scaling much inside the host, so data directory is picked simply based on disk usage.

```
path:
  data:
  - /srv/elasticsearch/0
  - /srv/elasticsearch/1
  logs: /var/log/elasticsearch
```

# redis

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

## Suricata config

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

## Testing

```
redis-cli
127.0.0.1:6379> KEYS *
1) "suricata"
```
# logstash

 * https://www.elastic.co/guide/en/logstash/master/index.html

```
LOGSTASH="logstash-6.1.2.deb"
[[ -f $LOGSTASH ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/logstash/$LOGSTASH -O $LOGSTASH
dpkg -s logstash || dpkg -i $LOGSTASH > /dev/null 2>&1
```

```
/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/suricata.conf -t || exit 1
```
# Common Event Expression

 * https://cee.mitre.org/
 * http://www.rsyslog.com/tag/cee-enhanced/

## Log format

```
Feb 25 11:23:42 suricata suricata[26526]: @cee: {"timestamp":"2015-12-07T19:30:54.863188+0000","flow_id":139635731853600,"pcap_cnt":142,"event_type":"alert","src_ip":"192.168.11.11","src_port":59523,"dest_ip":"192.168.12.12","dest_port":443,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":2013926,"rev":8,"signature":"ET POLICY HTTP traffic on port 443 (POST)","category":"Potentially Bad Traffic","severity":2}}
```

## Suricata configuration

```
grep cee -B2 -A3 /etc/suricata/suricata.yaml
```
