# Shipping Suricata logs to Elasticsearch

This section assumes that student can produce EVE JSON messages with Suricata and is familiar with basic Elastic setup.

* [Previous section](/Suricata/elastic) explained how Elastic works on high level and how to insert documents individually;
* however, this is very inefficient as every EVE message would be a separate HTTP request;
  * that's suicide;
* solution - clump a batch of messages and send a single big request;
* Elastic has `_bulk` API endpoint to pick them up;
  * 1000 or 10000 elements per bulk is not uncommon;
* Many methods exist to ship EVE into Elastic;
  * Up to your setup whatever works for you;
  * But, fundamentally, they all interact with `_bulk`;
  * So, basic understanding about how it works will be useful if things go wrong;
    * (and they most definitely will);

## Bulk API

## Filebeat

```
filebeat.inputs:
- type: log
  paths:
    - "/var/log/suricata/eve.json"
  json.keys_under_root: true
  json.add_error_key: true

processors:
- timestamp:
    field: timestamp
    layouts:
      - '2006-01-02T15:04:05Z'
      - '2006-01-02T15:04:05.999Z'
    test:
      - '2019-06-22T16:33:51Z'
      - '2019-11-18T04:59:51.123Z'

output.elasticsearch:
  hosts: ["elastic:9200"]
  index: "filebeat-%{+yyyy.MM.dd}"
  bulk_max_size: 10000

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

setup.template:
  name: 'filebeat'
  pattern: 'filebeat-*'
  enabled: false

setup.ilm.enabled: false
```

### Docker setup

For hipster cred, here's filebeat docker setup.

```
docker run -dit  --name filebeat -h filebeat -v /var/log/suricata:/var/log/suricata:ro  -v /var/log/filebeat:/var/log/filebeat:rw  -v /etc/filebeat.yml:/etc/filebeat.yml docker.elastic.co/beats/filebeat-oss:${ELASTIC_VERSION} run -c /etc/filebeat.yml
```
