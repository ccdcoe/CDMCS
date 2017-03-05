# Kibana

* https://www.elastic.co/guide/en/kibana/current/settings.html
* https://lucene.apache.org/core/2_9_4/queryparsersyntax.html
* [discover](https://www.elastic.co/guide/en/kibana/current/discover.html) -> [visualize](https://www.elastic.co/guide/en/kibana/current/visualize.html) -> [dashboard](https://www.elastic.co/guide/en/kibana/current/dashboard.html)
* [console](https://www.elastic.co/guide/en/kibana/current/console-kibana.html) -> [query](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html) -> [Aggregate](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations.html) -> [script](/Suricata/suricata/elaScripting.md)

## API queries

```
GET suricata-exercise/_search
{
  "size": 1,
  "query": {
    "bool": {
      "must": [
        {"term": {
          "event_type": {
            "value": "alert"
          }
        }}
      ]
    }
  }
}
```

```
GET suricata-exercise/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {
          "terms": {
            "event_type.keyword": [
              "alert"
            ]
          }
        }
      ]
    }
  },
  "aggs": {
    "tsBucketing": {
      "date_histogram": {
        "field": "timestamp",
        "interval": "hour"
      },
      "aggs": {
        "alerts": {
          "terms": {
            "field": "alert.category.keyword",
            "size": 15
          }
        }
      }
    }
  }
}
```

```
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {
          "term": {
            "event_type": {
              "value": "alert"
            }
          }
        },
        {
          "term": {
            "alert.severity": {
              "value": 1
            }
          }
        },
        {
          "wildcard": {
            "alert.category.keyword": {
              "value": "*Web*"
            }
          }
        }
      ],
      "must_not": [
        {
          "term": {
            "src_geoip.country_iso_code.keyword": {
              "value": "EE"
            }
          }
        }
      ]
    }
  },
  "aggs": {
    "signatures": {
      "terms": {
        "field": "alert.signature.keyword",
        "size": 25
      }
    }
  }
}
```
