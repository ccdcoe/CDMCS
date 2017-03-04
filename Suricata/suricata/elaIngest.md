# Elasticsearch Ingest node

* https://www.elastic.co/guide/en/elasticsearch/reference/master/ingest.html
* https://www.elastic.co/guide/en/elasticsearch/reference/master/ingest-processors.html
* https://www.elastic.co/guide/en/elasticsearch/plugins/master/ingest.html


```
/usr/share/elasticsearch/bin/elasticsearch-plugin install ingest-geoip
```

```
{
  "description": "Enrich Suricata logs with GeoIP",
  "processors": [
    {
      "geoip" : { "field": "src_ip", "target_field": "src_geoip" }
    },
    {
      "geoip" : { "field": "dest_ip", "target_field": "dest_geoip" }
    }
  ]
}
```

```
curl -XPUT localhost:9200/_ingest/pipeline/suricata -d @suricata_pipe.json
```
