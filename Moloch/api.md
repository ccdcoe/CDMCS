# API

* https://github.com/aol/moloch/wiki/API
* https://github.com/ccdcoe/otta/blob/master/python/main.py
* https://github.com/ccdcoe/CDMCS/blob/master/Moloch/vagrant/singlehost/tagger.py

## Simple queries with curl

Moloch uses digest authentication, this must be handled from whatever cli tool you use. If your moloch user name is not vagrant then change the `-u` parameter or add a new user through viewer.

```
curl -GET -u vagrant --digest 192.168.10.11:8005/connections.json | jq .
```
```
curl -GET -u vagrant --digest 192.168.10.11:8005/connections.csv
```
```
curl -GET -u vagrant --digest 192.168.10.11:8005/sessions.csv
```

## Adding query parameters

HTTP get parameters can be used to modify search results.

```
curl -GET -u vagrant --digest "192.168.10.11:8005/connections.json?length=10"
```

```
NOW=`date +%s`
THEN=$((NOW - 300))

curl -GET -u vagrant --digest "192.168.10.11:8005/connections.json" --data "length=10&startTime=$THEN&stopTime=$NOW"
```
