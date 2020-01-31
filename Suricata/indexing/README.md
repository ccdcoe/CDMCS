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
docker run \
  -ti \                                                     # Keep terminal open interactively
  --rm \                                                    # Remove container on docker stop / ctrl+c; you will lose all data unless you mounted a persistent volume
  --name my-first-elastic \                                 # Explicit container name, otherwise will be randomly chosen
  -p 9200:9200 \                                            # Forward host port 9200 to container port 9200
  -e "discovery.type=single-node" \                         # For single-node testing only,  dont use for cluster
  -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \                     # Minimal amount of Java heap to avoid running out of memory in Vagrant VM
  -e "cluster.name=cdmcs" \                                 # Cluster name, relevant for multihost clustered setup
    docker.elastic.co/elasticsearch/elasticsearch-oss:7.5.2 # Image source itself with version tag
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

## Playing with python

Great too for quick **interactive** scripting against Elastic (and other data sources) is to simply use a Jupyter notebook. Setting it up as regular user on modern machine with python3 is quite straightforward.

```
python3 -m pip install --user --upgrade jupyter jupyterlab
```

It is also a good idea to install some additional packages needed for interacting with our data sources.

```
python3 -m pip install --user elasticsearch redis pandas
```

Make sure that notebook is running. 

```
jupyter lab --ip=XXXX
```

Note that `ip` is needed if running notebook inside a vagrant VM, and it should correspond to private address of box that is accessible from hypervisor. Then look for the following line in console output:

```
    To access the notebook, open this file in a browser:
        file:///run/user/1000/jupyter/nbserver-11679-open.html
    Or copy and paste one of these URLs:
        http://ADDRESS:8888/?token=<TOKEN>
```

Then copy the URL into host machine browser if running jupyter inside Vagrant VM. Otherwise, if running from classroom laptop, the notebook should try to open the link with default browser.

 * [Playing with eve.json](001-load-eve.ipynb)
 * [Getting started with elasticsearch](002-elastic-intro.ipynb)

# Evebox

> Web Based Event Viewer (GUI) for Suricata EVE Events in Elastic Search

 * https://evebox.org/
 * https://github.com/jasonish/evebox

## Installing

Evebox is written in golang, so you actually just need to download a binary.

see:
 * https://evebox.org/files/development/
 * https://evebox.org/files/release/latest/

But there's nothing like firing up another container to host a simple Go binary.

```
docker pull jasonish/evebox
docker run -it -p 5636:5636 jasonish/evebox:master -e http://elasticsearch:9200
```

[Remember docker networks](/common/docker.md#networking) if experiencing elastic connectivity errors. Or use exposed host port, provided elastic is not limited to localhost.

```
docker run -it -p 5636:5636 --network elastic jasonish/evebox:master -e http://elasticsearch:9200
```


Up to you.

## Linking to elasticsearch

See evebox arguments.

```
evebox -h
```

**Do not expect an error message if elastic aggregation fails in background**. Just think of debuggin as fun little game. 

If running evebox from console gives no error but inbox/alerts displays no logs while events, then it's likely one of those problems:
 * events lack `.keyword` (es 5+) or `.raw` (es 2) field mappings;
   * or elasticsearch keyword argument missing;
   * missing index template;
 * event `@timestamp field missing`;

If events shows no logs while console displays no elastic connectivity errors, then your index pattern is likely wrong.

See `/etc/default/evebox` if installing from deb package.

# Scirius

> Scirius is a web application for Suricata ruleset management.

 * https://github.com/StamusNetworks/scirius
 * https://scirius.readthedocs.io/en/latest/installation-ce.html
 * https://www.stamus-networks.com/open-source/

## Setup

Scirius is a web application written on django framework. Nowadays it also includes nodejs, which has had some...issues. Official documentation works, this guide simply serves as helper on some important considerations.

Set up some python2 dependencies and clone the repo. Checkout version is out of date if you are from the future.

```
apt-get install -y python-pip dbconfig-common sqlite3 python-virtualenv
git clone https://github.com/StamusNetworks/scirius
cd scirius
```

Then start up virtualenv in local scirius folder. Install local deps into venv.

```
/usr/local/bin/virtualenv ./
source ./bin/activate

pip install -r requirements.txt
pip install --upgrade urllib3
pip install gunicorn pyinotify python-daemon
```

This is where the real *fun* begins. Let's pull a node version that actually works, set it up locally and freeze all versions. It's the [javascript way](https://en.wikipedia.org/wiki/Electron_(software_framework)).

```
NODE_VERSION="v10.18.1"
wget -4 -q https://nodejs.org/dist/$NODE_VERSION/node-$NODE_VERSION-linux-x64.tar.xz
tar -xJf node-$NODE_VERSION-linux-x64.tar.xz 
```

Remember those *issues* I mentioned earlier? Well, once upon a time, `npm` as `root` blew up your entire `/etc`. So now, if you try to build node packages as root user, you are going to have a bad time. Because, [nodejs modules written in c++](http://benfarrell.com/2013/01/03/c-and-node-js-an-unholy-combination-but-oh-so-right/) is a thing. So, everything is done as `vagrant` user with explicitly configured node module directory and paths.

```
mkdir ~/.npm-global
echo 'export PATH=~/.npm-global/bin:$PATH' > ~/.profile
echo "export PATH=$PWD/node-$NODE_VERSION-linux-x64/bin:\$PATH" > ~/.profile
source ~/.profile

npm config set prefix '~/.npm-global'
```

Now we can proceed with official guidelines.

```
npm install -g npm@latest webpack@3.11
npm install
cd hunt
npm install
npm run build
cd ..
```

Run database migrations.

```
python manage.py migrate
```

Generate CSS stuff.

```
/home/vagrant/.npm-global/bin/webpack
```

Collect static CSS assets.

```
python manage.py createsuperuser
```

Then see [local cofiguration](https://github.com/ccdcoe/CDMCS/blob/2019/Suricata/vagrant/singlehost/provision.sh#L652) for pointing scirius to elastic.

# Kibana

The most well-known frontend for elastic stack. And easiest to set up. Basic config involes just pointing toward elastic proxy. Note that image should be in same private network as elasticsearch cluster if docker is used. Alternatively, kibana can also be pointed toward exposed elastic proxy on host. Default port is `5601`, host port should be forwarded there to enable http access.

```
docker run \
  -it \
  --name kibana \
  -h kibana \
  --network cdmcs  \
  -e "SERVER_NAME=kibana" \
  -e "ELASTICSEARCH_URL=http://elastic:9200" \ # Deperecated in elastic 7 in favor of ELASTICSEARCH_HOSTS
  -p 5601:5601 \
    docker.elastic.co/kibana/kibana-oss:7.5.2
```

Then visit exposed port in web browser. Create a new index pattern under `management` > `Index Patterns`. This will allow you to use `Discover` and `Visuzalize` tabs. But most useful tab by far is `Dev tools` which functions as autocomplete-enabled IDE for elastic API. You can test any previously used curl or python queries in this tab.

---

[back](/Suricata)
