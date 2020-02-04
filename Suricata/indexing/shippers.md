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
