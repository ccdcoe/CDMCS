# install elasticsearch

 * https://www.elastic.co/guide/en/elasticsearch/reference/current/_installation.html
 * https://www.elastic.co/guide/en/elasticsearch/reference/current/deb.html
 * https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html

## install java 8

### openjdk (only for testing)
```
apt-get -y install openjdk-8-jre-headless
```

### oracle java
```
install_oracle_java() {
  echo "Installing oracle Java"
  echo 'oracle-java8-installer shared/accepted-oracle-license-v1-1 boolean true' | debconf-set-selections \
  && add-apt-repository ppa:webupd8team/java \
  && apt-get update > /dev/null \
  && apt-get -y install oracle-java8-installer > /dev/null
}
```

## deb package
```bash
ELASTICSEARCH="elasticsearch-6.1.2.deb"

[[ -f $ELASTICSEARCH ]] || wget  -4 https://artifacts.elastic.co/downloads/elasticsearch/$ELASTICSEARCH
dpkg -i $ELASTICSEARCH
systemctl enable elasticsearch
systemctl start elasticsearch
```

## test it

```
curl -ss -XGET localhost:9200
curl -ss -XGET localhost:9200/_cat/nodes
curl -ss -XGET localhost:9200/_cat/indices
curl -ss -XGET localhost:9200/_cat/shards
```

----
next -> [configure basic node](elastic.config.basic.md)
