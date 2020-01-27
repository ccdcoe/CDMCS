# Building Moloch from source

see
* https://github.com/aol/moloch#building-and-installing
* https://github.com/aol/moloch/wiki/Settings#Basic_Settings
* https://nodejs.org/en/download/package-manager/


Install dependencies. 

```
pkg install openjdk8 elasticsearch6 node8 lua53 wget curl pcre flex bison
pkg install gettext e2fsprogs-libuuid glib gmake p5-JSON
```

Set up ES java heap size.

```
vmstat
vim /usr/local/etc/elasticsearch/jvm.options
```

Rule of thumb is 50 per cent of all system memory but no more than 31(ish) gigabytes. It's okay to use less for testing environment that also houses moloch capture, viewer, wise, etc.

```
-Xms512m
-Xmx512m
```

Start ES service

```
sysrc elasticsearch_enable=YES
service elasticsearch start
```

```
curl -ss -XGET 127.0.0.1:9200/_cat/nodes
```

## Moloch

### Nodejs

Dependency for viewer. Node 8.9 is required for Moloch 1.0.0 and beyond, 6.13 for 0.50 and older.

* https://nodejs.org/dist/

### get the source
```
git clone https://github.com/aol/moloch
cd moloch
git checkout -b 'v1.1.0'
```

### configure, make install

 * PS! Check the filesystem paths. Chosen `/opt/moloch` is arbitrary choice of the instructor and may not reflect your environment. Vagrant build machine will use non-privileged directory in user home directory.

```
./easybutton-build.sh -d /opt/moloch
sudo gmake install
```

### Basic configuration

Download geoIP databases.

```
cd /opt/moloch/bin
cat ./moloch_update_geo.sh
```

Create unprivileged user

```
pw group add moloch
pw user add moloch -g moloch -s /usr/bin/false 
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

Create user for viewer

```
cd /opt/moloch/viewer
nodejs addUser.js -c /opt/moloch/etc/config.ini
```

Start viewer

```
nodejs viewer.js -c /opt/moloch/etc/config.ini
```

### testing capture without viewer

```
curl 127.0.0.1:9200/_cat/indices
```

 * expect to see index `sessions2-YYMMDD`
  * problem with capture if missing, please read capture console logs carefully
 * if present, check if you actually have messages in the index

```
curl 127.0.0.1:9200/sessions2-YYMMDD/_search?pretty
```
```
ls -lah /srv/pcap
tcpdump -r *.pcap -c1
curl -ss -XGET 127.0.0.1:9200/_cat/indices
curl -ss -XGET 127.0.0.1:9200/sessions-*/_search?pretty -d '{"size":1}'
```

### Finally, ...

* pushing to background (&, nohup, stdout/stderr)
* rc
* data retention

---
[next : Advanced Configuration](/Moloch/config.md)
