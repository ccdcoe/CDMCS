# Clustering

  * https://github.com/aol/moloch/wiki/Architecture#multiple-hosts-monitoring-multiple-network-segments
  * https://github.com/aol/moloch/wiki/Architecture#multiple-hosts-monitoring-high-traffic-networks
  * https://github.com/aol/moloch/wiki/Architecture#multiple-clusters

## Clustered elasticsearch

Elastic config options are in `elasticsearch.yml`. It should be placed under `/etc/elasticsearch` if installed from deb or bound under `/usr/share/elasticsearch/config/elasticsearch.yml` if running from docker images. Also, make sure that each node is bound to distinct port on host if running from container.

```
docker run -ti -p 9200:9200 -p 9300:9300 -v $PWD/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" docker.elastic.co/elasticsearch/elasticsearch-oss:6.7.1
```

Note that this creates a standard bridged docker network internal to your host. However, elasticsearch hosts need to be able to ping each other, which obviously won't work if nodes are unaware of each others actual networks. A node would also start advertising its internal address. **This breaks node-to-node connectivity and won't allow you to establish a cluster**.

In reality, you would solve this via setting up a docker swarm and using a node-spanning overlay network. In classroom setting, the easiest hack would be to bind elastic to `host` network and bypass docker private networking altogether. So, `-p 9200:9200 -p 9300:9300` should be replaced by `--network host`. If container is already bound to host network stack, then port forwarding is not needed. 

Now we can start configuring the node itself. Note that `$PWD/elasticsearch.yml` does not exists yet. **You have to create it**. **It does not matter where it is located on host (at least, for the purpose of training)**. Firstly, all nodes should be configured to belong to common cluster.

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
elasticsearch=192.168.10.14:9200,192.168.10.36:9200
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

Local node may also need this.

```
127.0.1.1 some-host-123
```

And also inform our viewer of her new name.

```
../bin/node viewer.js -c ../etc/config.ini --host some-host-123
```

You should then be able to open the session as before.

### node override

What if we wanted to run multiple moloch nodes on the same capture box? We could make multiple `config.ini` files but managing them might become a hassle, as most config options would be identical. Instead, we can override some config parameters based on `--node` argument of cature or viewer. Suppose we have a central router/firewall with multiple interfaces. We want to capture traffic from all interfaces and also filter that traffic by interface, as connection may come in from one NIC and go out from another, thus duplicating the session. We can add this into the `config.ini`.

```
[interface1]
interface=enp0s3
viewPort = 8005

[interface2]
interface=enp0s8
viewPort = 8006
```

Then start the capture process as follows.

```
./moloch-capture -c ../etc/config.ini --node interface1
```

And another process like so.

```
./moloch-capture -c ../etc/config.ini --node interface2
```

Initial config param for `interfaces` will be overrided based on node name. We can make this more manageable by also creating a systemd service file `/etc/systemd/system/moloch-capture@.service`.

```
[Unit]
Description=manages my worker service, instance %i
After=multi-user.target moloch-viewer.service

[Service]
Type=simple
User=root
ExecStart=/data/moloch/bin/moloch-capture -c /data/moloch/etc/config.ini --node interface%i
Restart=always
```

And after a simple `systemctl daemon-reload`, we can start these services in a loop.

```
systemctl start moloch-capture-reader\@{1..2}.service
```

This should also reflect in viewer.

```
nohup ../bin/node viewer.js -c ../etc/config.ini -n interface1 &
nohup ../bin/node viewer.js -c ../etc/config.ini -n interface2 &
```

And in our hosts file hack.

```
127.0.1.1       interface1
127.0.1.1       interface2
```

We should then be able to connect to port `8005` and `8006` of our capture box and read sessions from both. Note that `--host` basically becomes redundant, as `node` field would be otherwise be derived from that. Now we set it explicitly.

## Tasks

  * You will be assigned into a group of 4-6 people and your task is to design a multi-viewer, multi-capture, multi-elasticsearch moloch cluster;
    * You have to decide who hosts the following roles:
      * es master;
      * es data;
      * es proxy;
      * wise;
      * redis data source;
      * live capture;
      * offline forensics capture (should process pcaps from [this site](https://malware-traffic-analysis.net/));
    * One node can hold multiple roles, or run multiple moloch nodes, but no one person should carry all the load;
    * You can increase the number of nodes in Vagrantfile, but make sure you have enough RAM;

## Sending sessions between clusters

For sending sessions to another cluster, we would only need to define this section. Note that `passwordSecret` corresponds to the config parameter of remote cluster `config.ini`.

```
[moloch-clusters]
singlehost=url:http://singlehost:8005;passwordSecret:test123;name:Single host easy button
```

As always, we also need to know where the remote viewer is.

```
192.168.10.11   singlehost
```

## Parliament

 * https://github.com/aol/moloch/tree/master/parliament

In the `parliament` folder, run the app as any other NodeJS thing.

```
../bin/node parliament.js
```

Note that there is now a `parliament.json` file. You can also visit port `8008` of your box now. Set the password (and be more creative).

```
curl -s -XPUT  localhost:8008/parliament/api/auth/update -d newPassword=admin
```

Assuming no prior config, it should return a new API token as JSON key. We can use that token to add a group.

```

curl -s \
  -XPOST \
  -H "Content-Type: application/json;charset=UTF-8" \
  localhost:8008/parliament/api/groups \
  --data "{\"token\":\"${token}\", \"title\":\"${GROUP}\"}"

```

This should give us the ID of our new group. Clusters can be added under these groups.

```
curl -s \
  -XPOST \
  -H "Content-Type: application/json;charset=UTF-8" \
  localhost:8008/parliament/api/groups/${id}/clusters \
  --data "{\"token\":\"${token}\", \"title\":\"singlehost\",\"url\":\"http://singlehost:8005\"}"
```

## Multies

 * https://molo.ch/settings#multi-viewer-settings

## Tasks

  * Configure your viewers to be able to send and receive sessions from other groups;
  * Set up parliament on one host, configure it to connect to all classroom clusters;
  * Set up multies.js and multi-viewer process, configure them to be able to connect to all classroom clusters;
  * Parliament, multies and multi-viewer processes should ideally run on different cluster nodes;
