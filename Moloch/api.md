# API

* https://github.com/aol/moloch/wiki/API
* https://github.com/ccdcoe/otta/blob/master/python/main.py
* https://github.com/ccdcoe/CDMCS/blob/master/Moloch/vagrant/singlehost/tagger.py

# Simple queries with curl

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

## Using query parameters

HTTP get parameters can be used to modify search results.

```
curl -GET -u vagrant --digest "192.168.10.11:8005/connections.json?length=10"
```

```
NOW=`date +%s`
THEN=$((NOW - 300))

curl -GET -u vagrant --digest "192.168.10.11:8005/connections.json" --data "length=10&startTime=$THEN&stopTime=$NOW"
```

Standard viewer queries can be placed after `expression` parameter to narrow down the results.

```
curl -GET -u vagrant --digest "192.168.10.11:8005/connections.json" --data "length=10&startTime=$THEN&stopTime=$NOW&expression=" --data-urlencode "ip==192.168.10.11"
```

## Adding tags to connections

Tags can be added by sending a POST request to desired sessions. Query parameters are same as connectons API, but comma-separated list of tags can be sent via HTTP POST body.

```
curl -POST -u vagrant --digest "192.168.10.11:8005/addTags?startTime=$THEN&stopTime=$NOW&expression=" --data "tags=myfirsttag,hello"
```

# Scripting with python3

## Requesting data with HTTP GET
```
#!/usr/bin/env python3

import urllib3, requests
import time
import json

def query(start, stop, expr):
        return {
                "startTime": start,
                "stopTime": stop,
                "expression": expr
        }

host = "http://192.168.10.11:8005/"
user = "vagrant"
passwd = user

now = int(time.time())
then = now - 300
expressions = [
        "ip==192.168.10.11",
        "ip==192.168.10.1",
        "(ip==192.168.10.1||ip==192.168.10.11)&&port==443"
        ]

apis = [
        "connections.json",
        "sessions.json"
        ]

queries = [ query(then, now, e) for e in expressions ]
queries = [ urllib3.request.urlencode(q) for q in queries ]

for api in apis:
        for q in queries:
                url = host + api + "?" + q
                resp = requests.get(url, auth=requests.auth.HTTPDigestAuth(user, passwd))
                data = json.loads(resp.text)
                print(data)
```

## Adding data with HTTP POST

```
#!/usr/bin/env python3

import urllib3, requests
import time
import json

def query(start, stop, expr):
        return {
                "startTime": start,
                "stopTime": stop,
                "expression": expr
        }

def tagData(tags): return { "tags": ','.join(tags) }

host = "http://192.168.10.11:8005/"
user = "vagrant"
passwd = user

now = int(time.time())
then = now - 300
expressions = [
        "ip==192.168.10.11",
        "ip==192.168.10.1"
        ]

tags = [
        "tag1",
        "tag2",
        "tag3"
        ]
tags = tagData(tags)

queries = [ query(then, now, e) for e in expressions ]
queries = [ urllib3.request.urlencode(q) for q in queries ]

start = int(time.time() * 1000)

for q in queries:
        url = host + "addTags?" + q
        resp = requests.post(url, auth=requests.auth.HTTPDigestAuth(user, passwd), data=tags)
        print(resp.text)

took = int(time.time() * 1000) - start
print(took, "ms")
```

## Async queries with python asyncio

 * running HTTP queries one at a time and waiting for each to complete before starting next one is very inefficient in practice
 * profound speed difference with higher bulk size
 * python 3.4 needed for this example to work, tested on 3.5
 * extends previous script
 * `functools.partial` is used as asynio wrapper cannot take named arguments

```
import asyncio
import functools
import concurrent.futures

async def AsyncFlush():

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(queries)) as executor:
                loop = asyncio.get_event_loop()
                futures = [ loop.run_in_executor( executor, functools.partial(requests.post, host + "addTags?" + q, data=tags, auth=requests.auth.HTTPDigestAuth(user, passwd)) ) for q in queries ]

                success = 0
                for resp in await asyncio.gather(*futures):
                        print(resp.text)


start = int(time.time() * 1000)

loop = asyncio.get_event_loop()
loop.run_until_complete(AsyncFlush())

took = int(time.time() * 1000) - start
print(took, "ms")
```
