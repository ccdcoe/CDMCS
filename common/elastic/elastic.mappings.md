# Fixing mappings

* https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html
* https://raw.githubusercontent.com/markuskont/salt-elasticsearch/master/salt/elasticsearch/etc/elasticsearch/template/suricata.json

## Templates

```
curl -XGET localhost:9200/_template
```

```
{
 "order" : 0,
 "version" : 0,
 "template" : "*",
 "settings" : {
   "index" : {
     "refresh_interval" : "60s",
     "number_of_shards" : 1,
     "number_of_replicas" : 0
   }
 },
 "mappings" : {
   "_default_" : {
     "dynamic_templates" : [
       {
         "message_field" : {
           "path_match" : "message",
           "mapping" : {
             "norms" : false,
             "type" : "text"
           },
           "match_mapping_type" : "string"
         }
       },
       {
         "string_fields" : {
           "mapping" : {
             "norms" : false,
             "type" : "text",
             "fields" : {
               "keyword" : {
                 "type" : "keyword"
               }
             }
           },
           "match_mapping_type" : "string",
           "match" : "*"
         }
       }
     ],
     "_all" : {
       "norms" : false,
       "enabled" : false
     },
     "properties" : {
       "@timestamp" : {
         "type" : "date",
         "format": "strict_date_optional_time||epoch_millis||date_time"
       },
       "geoip" : {
         "dynamic" : true,
         "properties" : {
           "ip" : { "type" : "ip" },
           "latitude" : { "type" : "half_float" },
           "location" : { "type" : "geo_point" },
           "longitude" : { "type" : "half_float" }
         }
       },
       "@version" : {
         "include_in_all" : false,
         "type" : "keyword"
       }
     }
   }
 },
 "aliases" : { }
}
```

```
curl -XPUT localhost:9200/_template/default -d @default.json
```

## Reindex and update_by_query API

* https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/tasks.html
* https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-update-by-query.html
