# Building Moloch from source

see
* https://www.elastic.co/guide/en/elasticsearch/reference/current/deb.html
* https://github.com/aol/moloch#building-and-installing
* https://github.com/aol/moloch/wiki/Settings#Basic_Settings
* https://nodejs.org/en/download/package-manager/

## Elasticsearch

Install dependencies

```
apt-get install -y openjdk-8-jre-headless apt-transport-https
```

Install elasticsearch (5)

```
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.3.1.deb
dpkg -i elasticsearch-5.3.1.deb
```

Set up ES java heap size.

```
free -m
vim /etc/elasticsearch/jvm.options
```

```
-Xms512m
-Xmx512m
```

Start ES service

```
systemctl enable elasticsearch.service
systemctl start elasticsearch.service
systemctl status elasticsearch.service
```

```
curl -ss -XGET localhost:9200/_cat/nodes
```

## Moloch

### Dependencies

* https://nodejs.org/dist/

```
sudo apt-get -y install build-essential git
curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### get the source
```
git clone https://github.com/aol/moloch
cd moloch
git checkout -b 'v0.18.2'
```

### configure, make install

```
./easybutton-build.sh -d /opt/moloch
sudo make install
```

### Basic configuration

Download geoIP databases

```
cd /opt/moloch/bin
cat ./moloch_update_geo.sh
```

Create unprivileged user

```
groupadd moloch
useradd -s /bin/false -g moloch moloch
```

Create PCAP storage directory. Set permissions

```
mkdir /srv/pcap
chown -R moloch:moloch /srv/pcap
usermod -d /srv/pcap moloch
```

```
cd /opt/moloch/etc
cp config.ini.sample config.ini
vim config.ini
```

* Point moloch to ES HTTP proxy(s)
* Set capture interface
* PCAP storage directory
* geoIP, ASN, RIR database locations
* unprivileged user/group

Create moloch database

```
cd /opt/moloch/db
./db.pl --help
```

Start moloch-capture

```
/opt/moloch/bin/moloch-capture --help
```

Verify FPC data (initial)

```
ls -lah /srv/pcap
tcpdump -r *.pcap -c1
curl -ss -XGET localhost:9200/_cat/indices
curl -ss -XGET localhost:9200/sessions-*/_search?pretty -d '{"size":1}'
```

Create user for viewer

```
cd /opt/moloch/viewer
nodejs addUser.js -c /opt/moloch/etc/config.ini
```

Start viewer

```
nodejs viewer.js -c /opt/moloch/etc/config.ini
```

### Finally, ...

* pushing to background (&, nohup, stdout/stderr)
* systemd/upstart/sysvinit
* data retention

---
[next : Advanced Configuration](/Moloch/config.md)
