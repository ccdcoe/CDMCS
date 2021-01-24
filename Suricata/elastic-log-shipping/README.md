# Shipping Suricata logs to Elasticsearch

This section assumes that student is familiar with:
* Suricata on CLI, configuring it, using rulesets and parsing or replaying PCAP files;
* Getting Elastic up and running with docker, interacting with `/_cat` and `_search` API endpoints;

* https://suricata.readthedocs.io/en/latest/output/eve/eve-json-output.html#output-types

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

* [basics](/Suricata/elastic-log-shipping/000-bulk-intro.ipynb)
* [shipping EVE](/Suricata/elastic-log-shipping/000-bulk-eve.ipynb)

## Filebeat

* https://www.elastic.co/downloads/beats/filebeat-oss

Beats family is a very popular choice for client-side log shipping nowadays. It's a Go binary, so it does not have any external dependencies. Any compatible OS architecture should be able to execute the compiled binary. That's nice, because it also means we don't need containers to keep dependencies in check. Most simple setup is to download the package and run it!

**Mind the version, it must be the same as Elasticsearch you are already running**.

```
wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-7.10.2-linux-x86_64.tar.gz
tar -xzf filebeat-oss-7.10.2-linux-x86_64.tar.gz
cd filebeat-7.10.2-linux-x86_64/
ls -lah
```

You should see something like this.

```
total 69M
drwxr-xr-x  5 root root 4.0K Jan 22 10:02 .
drwx------  6 root root 4.0K Jan 22 10:02 ..
-rw-r--r--  1 root root   41 Jan 12 22:13 .build_hash.txt
-rw-r--r--  1 root root 291K Jan 12 22:10 fields.yml
-rwxr-xr-x  1 root root  61M Jan 12 22:12 filebeat
-rw-r--r--  1 root root  90K Jan 12 22:10 filebeat.reference.yml
-rw-------  1 root root 9.8K Jan 12 22:10 filebeat.yml
drwxr-xr-x  3 root root 4.0K Jan 12 22:10 kibana
-rw-r--r--  1 root root  12K Jan 12 21:58 LICENSE.txt
drwxr-xr-x 22 root root 4.0K Jan 12 22:10 module
drwxr-xr-x  2 root root 4.0K Jan 12 22:10 modules.d
-rw-r--r--  1 root root 8.2M Jan 12 22:00 NOTICE.txt
-rw-r--r--  1 root root  814 Jan 12 22:13 README.md
```

And then explore the built-in help dialog for filebeat.

```
./filebeat --help
./filebeat run --help
```

Filebeat uses subcommands, as many CLI applications do. Main one being `run`. While you can override config options on command line, a better option is to use `-c` to point it toward a custom config file. Example skeletons are already in the folder, **but they are not enough**.

Filebeat must be configured to:
* load your EVE JSON file, *where ever you decided to store it*;
* parse each message for JSON data, store that decoded JSON in elastic message root;
* parse message timestamp to get `@timestamp` logstash-style field, many frontend tools assume it to be there and can break silently if it's not;
* output stream should be pointed **toward your elastic instance**;
* choose the index you want to store the data;

Other options are simply nice improvements and demonstration. For example, redefining template patterns, disabling it if you want, customizing elastic index pattern, helpful filebeat logging, etc. 

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
      - '2006-01-02T15:04:05.999999Z0700'
      - '2006-01-02T15:04:05Z'
      - '2006-01-02T15:04:05.999Z'
    test:
      - '2020-03-12T21:36:17.712650+0200'
      - '2019-06-22T16:33:51Z'
      - '2019-11-18T04:59:51.123Z'

output.elasticsearch:
  hosts: ["localhost:9200"]
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
```

**Note that this configuration also disables template management.** It assumes ECS patterns (more on that later) which we are not using. It does not configure dual-mapping that is assumed by many front-end tools, and thus breaks them. Alas, many frontend tools are accustomed to Logstash default configurations and have adopted them as requirements.

This mapping is in `fields.yml` file that could be customized, or reconfigured. But it's easier to set the template manually. Following command will set a template that is derived from logstash default dual-mapping setup.

```
curl -XPUT localhost:9200/_template/logstash -H 'Content-Type: application/json' -d '{"order": 0, "version": 0, "index_patterns": ["logstash-*", "events-*", "suricata-*", "filebeat-*"], "settings": {"index": {"number_of_shards": 3, "number_of_replicas": 0, "refresh_interval": "5s"}}, "mappings": {"dynamic_templates": [{"message_field": {"path_match": "message", "mapping": {"norms": false, "type": "text"}, "match_mapping_type": "string"}}, {"string_fields": {"mapping": {"norms": false, "type": "text", "fields": {"keyword": {"type": "keyword"}}}, "match_mapping_type": "string", "match": "*"}}], "properties": {"@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis||date_time"}, "@version": {"type": "keyword"}, "ip": {"type": "ip"}}}, "aliases": {}}'
'
```

Assuming you have this config **customized to your environment** in `config.yml`, use the `run` command.

```
./filebeat run -c config.yml
```

Assuming you kept the default `filebeat` index pattern and are running local docker Elastic on a VM, then verify that you have logs in elastic. **If not, go back to config bulletpoints and verify that you customized each item correctly**.

```
curl localhost:9200/filebeat-*/_search
```

### Word about ECS

Elastic Common Schema tries to address a simple issue - Elastic has no schema. This makes it great for *"let's collect everything and figure out what we need later"* role, but leads to way too many fields that are inconsistent across data sources, too many fields types to manage, mapping collisions, key inconsistencies while doing lookups, and too much JSON verbosity.

ECS is a taxonomy that tackles those problems by...making more fields. Not much is left of original message structure and a ton of metadata is added as well. That metadata has limited use outside Elastic product stack.

Filebeat has Suricata plugin for doing that, but this is not maintained by Suricata developers. Our course focuses only on core EVE, as that already has over 1000 possible fields depending on configuration.

### Docker setup

For hipster cred, here's filebeat docker setup. However, doing this overkill for this exercise.

```
docker run -dit  --name filebeat -h filebeat -v /var/log/suricata:/var/log/suricata:ro  -v /var/log/filebeat:/var/log/filebeat:rw  -v /etc/filebeat.yml:/etc/filebeat.yml docker.elastic.co/beats/filebeat-oss:${ELASTIC_VERSION} run -c /etc/filebeat.yml
```
