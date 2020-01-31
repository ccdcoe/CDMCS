# Scalable indexing

Single-node setups only get you so far. At one point you have to scale out.

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
    docker.elastic.co/elasticsearch/elasticsearch-oss:7.5.2
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
    docker.elastic.co/elasticsearch/elasticsearch-oss:7.5.2
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

# Alerta

Alerting tends to turn whatever tool is used into a log server. E-mail is especially bad for this. But you need to know what the situation is right now, how the alert levels have elevated or dropped, how the alerts correspond to your assets, how the alerts are correlated, etc. Alerta is the tool for doing that.

 * https://docs.alerta.io/en/latest/quick-start.html

Alerta is simply a python API supported by a mongodb database (though is not the only option). Firstly, we need to set up our mongo instance. There are two methods:

 * [set up debian ppa](https://docs.mongodb.com/master/tutorial/install-mongodb-on-ubuntu/)
 * [use a docker image](https://docs.docker.com/samples/library/mongo/)

Mongo only needs to be accessible to alerta api daemon. And `localhost` is good enough for testing environment. Then install CLI tool and daemon from pip. Note that `$HOME/.local/bin` should be in path for subsequent commands.

```
python3 -m pip install --user alerta alerta-server
```

Then run the API server with default options while listening to all interfaces. Listening part is important because old web ui uses *CORS*.

```
alertad run --port 8080 --host 0.0.0.0
```

Speaking of *CORS*, we should update `/etc/alertad.conf` (or local version if you modified `ALERTA_SVR_CONF_FILE` env variable) for the ip/domain/port that will later be used for web ui!

```
CORS_ORIGINS = [
    'http://192.168.10.15:8000'
]
```

Note that you should use whatever IP/Port you decide to use. Vagrant box public ip should be added and port `8000` is simply for reference. Then set up the web ui.

```
wget -O alerta-web.tgz https://github.com/alerta/angular-alerta-webui/tarball/master
tar zxvf alerta-web.tgz
cd alerta-angular-alerta-webui-*/app
python3 -m http.server 8000
```

Make sure to edit `config.json` in `app` directory to point to correct endpoint.

```
{"endpoint": "http://192.168.10.15:8080"}
```

Due to *CORS*, this endpoint should be exposed to the user. So, localhost is not going to be good if you are serving it remotely.

**Important!** - Old web ui is deprecated. See [new web ui](https://github.com/alerta/beta.alerta.io) for future reference.

## Usage

Web ui is simply for colorful pictures, first verify that everything works via command line tool.

```
alerta send -r web01 -e NodeDown -E Production -S Website -s major -t "Web server is down." -v ERROR
```
```
alerta top
```

Then see the web ui. If it does not work, it is most likely *CORS* or *endpoint* in `app/config.json`

## Config

 * https://docs.alerta.io/en/latest/configuration.html?highlight=levels

Many things can be customized, including alert levels.

```
SEVERITY_MAP = {
    'erm, what!??': 1,
    'wat': 2,
    'interesting': 3,
    'ok': 4,
    'meh': 5
}
DEFAULT_NORMAL_SEVERITY = 'ok'  # 'normal', 'ok', 'cleared'
DEFAULT_PREVIOUS_SEVERITY = 'interesting'

COLOR_MAP = {
    'severity': {
            'erm, what!??': "red",
            'wat': "orange",
            'interesting': "yellow",
            'ok': "skyblue",
            'meh': "green"
    },
    'text': 'black',
    'highlight': 'skyblue '
}
```

## Housekeeping

Expired alerts do not go away by themselves, they have to be clean up via periodic cleanup job. Edit the crontab via `crontab -e`.

```
* * * * *  alerta housekeeping
```

# logstash

 * https://www.elastic.co/guide/en/logstash/master/index.html

```
LOGSTASH="logstash-7.5.2.deb"
[[ -f $LOGSTASH ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/logstash/$LOGSTASH -O $LOGSTASH
dpkg -s logstash || dpkg -i $LOGSTASH > /dev/null 2>&1
```

```
/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/suricata.conf -t || exit 1
```

```
input {
  redis {
    data_type => "list"
    host => "redis"
    port => 6379
    key  => "suricata"
    tags => ["suricata", "CDMCS", "fromredis"]
  }
}
filter {
  json {
    source => "message"
  }
  if 'syslog' not in [tags] {
    mutate { remove_field => [ "message", "Hostname" ] }
  }
}
output {
  elasticsearch {
    hosts => ["elasticsearch"]
    index => "logstash-bigindex"
  }
}
```

# Syslog

## Common Event Expression

 * https://cee.mitre.org/
 * http://www.rsyslog.com/tag/cee-enhanced/

### Log format

```
Feb 25 11:23:42 suricata suricata[26526]: @cee: {"timestamp":"2015-12-07T19:30:54.863188+0000","flow_id":139635731853600,"pcap_cnt":142,"event_type":"alert","src_ip":"192.168.11.11","src_port":59523,"dest_ip":"192.168.12.12","dest_port":443,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":2013926,"rev":8,"signature":"ET POLICY HTTP traffic on port 443 (POST)","category":"Potentially Bad Traffic","severity":2}}
```

### Suricata configuration

```
grep cee -B2 -A3 /etc/suricata/suricata.yaml
```

## Rsyslog

 * http://www.rsyslog.com/ubuntu-repository/
 * http://www.rsyslog.com/tag/mmjsonparse/
 * http://www.rsyslog.com/doc/mmjsonparse.html
 * http://www.rsyslog.com/doc/v8-stable/configuration/modules/omelasticsearch.html

```
apt-cache policy rsyslog
rsyslog:
  Installed: 7.4.4-1ubuntu2.6
  Candidate: 8.16.0-0adiscon1trusty1
  Version table:
     8.16.0-0adiscon1trusty1 0
        500 http://ppa.launchpad.net/adiscon/v8-stable/ubuntu/ trusty/main amd64 Packages
 *** 7.4.4-1ubuntu2.6 0
        500 http://archive.ubuntu.com/ubuntu/ trusty-updates/main amd64 Packages
        100 /var/lib/dpkg/status
```

### Installing missing modules

```
sudo apt-get install rsyslog-mmjsonparse rsyslog-elasticsearch -y
```

```
sudo service rsyslog restart
```

### Verify daemon

```
grep rsyslogd /var/log/syslog
```

### Client-server

#### client

```
echo "*.* @192.168.10.20:514" >> /etc/rsyslog.d/udp-client.conf
systemctl restart rsyslogd.service
```

#### server

```
cat > /etc/rsyslog.d/udp-server.conf <<EOF
module(load="imudp")
input(type="imudp" port="514")
EOF
```

```
systemctl restart rsyslogd.service
```

```
tail /var/log/syslog
```

## Filtering and elastic output

```
vim /etc/rsyslog.d/60-suricata-tag-to-file.conf
```

```
if $syslogtag contains 'suricata' then /var/log/suricata-tag.log
```

### Filtering using JSON parser

```
vim /etc/rsyslog.d/61-suricata-cee-to-file.conf
```
```
module(load="mmjsonparse")

action(type="mmjsonparse")

if $parsesuccess == "OK" then action(
    type="omfile"
    dirCreateMode="0700"
    FileCreateMode="0644"
    File="/var/log/suricata-cee.log"
)
```

### Enable high precision timestamps

```
sudo vim /etc/rsyslog.conf
```
```
#$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
```
```
sudo service rsyslog restart
```

### Parsing syslog timestamp

```
template(name="suricata-plaintext-index" type="list") {
    constant(value="/var/log/suricata-")
    property(name="timereported" dateFormat="rfc3339" position.from="1" position.to="4")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="6" position.to="7")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="9" position.to="10")
}
```

```
template(name="suricata-index" type="list") {
    constant(value="suricata-")
    property(name="timereported" dateFormat="rfc3339" position.from="1" position.to="4")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="6" position.to="7")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="9" position.to="10")
}
```

### Invoking a template for dynamic naming

```
local5.info     action(
    type="omfile"
    dirCreateMode="0700"
    FileCreateMode="0644"
    DynaFile="suricata-plaintext-index"
)
```

### Defining custom log message format

```
template(name="JSON" type="list") {
    property(name="$!all-json")
}
```

### Add syslog timestamp and hostname to JSON

```
template(name="JSON-with-syslog" type="list") {
  constant(value="{\"@timestamp\":\"")
  property(name="timereported" dateFormat="rfc3339")
  constant(value="\",\"hostname\":\"")
  property(name="hostname" format="json")
  constant(value="\",")
  property(name="$!all-json" position.from="2")
}
```

### Modify for flat log files

```
# Add syslog timestamp and hostname to JSON
template(name="JSON-with-syslog" type="list") {
  constant(value="{\"@timestamp\":\"")
  property(name="timereported" dateFormat="rfc3339")
  constant(value="\",\"hostname\":\"")
  property(name="hostname" format="json")
  constant(value="\",")
  property(name="$!all-json" position.from="2")
}
```

### Invoking elasticsearch output module

```
module(load="omelasticsearch")
action(
    type="omelasticsearch"
    template="JSON"
    server="127.0.0.1"
    serverport="9200"
    searchIndex="suricata-index"
)
```

### Final configuration

```
module(load="omelasticsearch")
module(load="mmjsonparse")

template(name="suricata-index" type="list") {
    constant(value="suricata-")
    property(name="timereported" dateFormat="rfc3339" position.from="1" position.to="4")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="6" position.to="7")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="9" position.to="10")
}

template(name="JSON" type="list") {
    property(name="$!all-json")
}

if $syslogtag contains 'suricata' and $msg startswith ' @cee:' then {

  action(type="mmjsonparse")

  if $parsesuccess == "OK" then action(
    type="omelasticsearch"
    template="JSON"
    server="127.0.0.1"
    serverport="9200"
    searchIndex="suricata-index"
    dynSearchIndex="on"
  )

}
```
