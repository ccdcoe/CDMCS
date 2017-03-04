# Simple filtering

```
vim /etc/rsyslog.d/60-suricata-tag-to-file.conf
```

```
if $syslogtag contains 'suricata' then /var/log/suricata-tag.log
```

# Filtering using JSON parser

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

# Enable high precision timestamps

```
sudo vim /etc/rsyslog.conf
```
```
#$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
```
```
sudo service rsyslog restart
```

# Parsing syslog timestamp

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

# Invoking a template for dynamic naming

```
local5.info     action(
    type="omfile"
    dirCreateMode="0700"
    FileCreateMode="0644"
    DynaFile="suricata-plaintext-index"
)
```

# Defining custom log message format

```
template(name="JSON" type="list") {
    property(name="$!all-json")
}
```

## Add syslog timestamp and hostname to JSON

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

## Modify for flat log files

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

# Invoking elasticsearch output module

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

# Final configuration

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

# Testing

```
curl -XGET localhost:9200/suricata-index/_search?pretty -d '{"size": 2}'
```

```
curl -XGET localhost:9200/suricata-index/_mapping?pretty
```

# Fixing mappings

* https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html

```
curl -XGET localhost:9200/_template
```

```
{
 "order" : 10,
 "version" : 0,
 "template" : "suricata-*",
 "mappings" : {
   "_default_" : {
     "properties" : {
       "alert": {
         "properties": {
           "gid": { "type": "integer" },
           "rev": { "type": "integer" },
           "severity": { "type": "integer" },
           "signature_id": { "type": "integer" }
         }
       },
       "dest_geoip": {
         "properties": {
           "location" : { "type" : "geo_point" }
         }
       },
       "dest_ip": { "type": "ip" },
       "dest_port": { "type": "integer" },
       "dns": {
         "properties": {
           "id": { "type": "integer" },
           "ttl": { "type": "integer" },
           "tx_id": { "type": "integer" }
         }
       },
       "fileinfo": {
         "properties": {
           "size": { "type": "integer" },
           "stored": { "type": "boolean" },
           "tx_id": { "type": "integer" }
         }
       },
       "flow_id": { "type": "long" },
       "http": {
         "properties": {
           "length": { "type": "integer" },
           "status": { "type": "integer" }
         }
       },
       "icmp_code": { "type": "integer" },
       "icmp_type": { "type": "integer" },
       "packet": { "type": "binary" },
       "packet_info": {
         "properties": {
           "linktype": { "type": "integer" }
         }
       },
       "payload": { "type": "binary" },
       "src_geoip": {
         "properties": {
           "location" : { "type" : "geo_point" }
         }
       },
       "src_ip": { "type": "ip" },
       "src_port": { "type": "integer" },
       "ssh": {
         "properties": {
           "client": {
             "properties": {
               "proto_version": { "type": "double" }
             }
           },
           "server": {
             "properties": {
               "proto_version": { "type": "double" }
             }
           }
         }
       },
       "stream": { "type": "integer" },
       "timestamp": { "type": "date" },
       "tls": {
         "properties": {
           "notafter": { "type": "date" },
           "notbefore": { "type": "date" }
         }
       },
       "tx_id": { "type": "integer" }
     }
   }
 },
 "aliases" : { }
}
```
