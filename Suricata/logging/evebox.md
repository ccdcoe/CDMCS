# Evebox send alerts to elasticsearch

see:

* configure https://github.com/jasonish/evebox/blob/master/cmd/esimport/esimport.go#L93
* template https://github.com/jasonish/evebox/blob/master/resources/elasticsearch/template-es5x.json


```
evebox esimport -e http://localhost:9200 --index suricata --end /var/log/suricata/eve.json
```
