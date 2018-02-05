# Fixing mappings

* https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html
* https://raw.githubusercontent.com/markuskont/salt-elasticsearch/master/salt/elasticsearch/etc/elasticsearch/template/suricata.json
* https://www.elastic.co/blog/strings-are-dead-long-live-strings
* https://www.elastic.co/guide/en/elasticsearch/reference/current/multi-fields.html

## Templates

```
curl -XGET localhost:9200/_template
```

```
{
  "order": 0,
  "version": 60001,
  "index_patterns": [
    "*"
  ],
  "settings": {
    "index": {
      "refresh_interval" : "30s",
      "number_of_shards" : 3,
      "number_of_replicas" : 0
    }
  },
  "mappings": {
    "_default_": {
      "dynamic_templates": [
        {
          "message_field": {
            "path_match": "message",
            "match_mapping_type": "string",
            "mapping": {
              "type": "text",
              "norms": false
            }
          }
        },
        {
          "string_fields": {
            "match": "*",
            "match_mapping_type": "string",
            "mapping": {
              "type": "text",
              "norms": false,
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            }
          }
        }
      ],
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "@version": {
          "type": "keyword"
        },
        "geoip": {
          "dynamic": true,
          "properties": {
            "ip": {
              "type": "ip"
            },
            "location": {
              "type": "geo_point"
            },
            "latitude": {
              "type": "half_float"
            },
            "longitude": {
              "type": "half_float"
            }
          }
        }
      }
    }
  },
  "aliases": {}
}
```

```
curl -ss -XPUT localhost:9200/_template/default -d @/vagrant/elastic-default-template.json -H'Content-Type: application/json'
```

## check for mappings

```
curl -ss -XGET localhost:9200/index-timestamp/_mappings
```

## Reindex and update_by_query API

* https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/tasks.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-update-by-query.html
