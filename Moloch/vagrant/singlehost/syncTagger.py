#!/usr/bin/env python

import redis
import time
from datetime import datetime
#import asyncio
import urllib3, requests
import json

def rfc3339toEpoch(ts):
    ts = datetime.strptime(msg["timestamp"], '%Y-%m-%dT%H:%M:%S.%f%z')
    return int(time.mktime(ts.timetuple())) + 10800

def pullRedisAlertList(host="localhost", port=6379, db=0, key="foo"):
    r = redis.Redis(host=host, port=port, db=db)
    for msg in r.lrange(key, 0, -1):
        try:
            msg = json.loads(msg)
            yield msg if msg["event_type"] == "alert" else next
        except:
            next

def getQuery(sip, sprt, dip, dprt): 
    return "ip.src = %s && ip.dst = %s && port.src = %s && port.dst = %s" % ( sip, dip, sprt, dprt)

MHOST="192.168.10.11"
MPORT=8005
REDIS=MHOST
MUSER="vagrant"
MPASS="vagrant"

base="http://%s:%s/addTags?" % (MHOST, MPORT)
for msg in pullRedisAlertList(host=REDIS, key="suricata"):
    try:
        ts = rfc3339toEpoch(msg["timestamp"])
        expression = getQuery(sip=msg["src_ip"], dip=msg["dest_ip"], sprt=msg["src_port"], dprt=msg["dest_port"])
        query = {
                "expression": expression,
                "startTime": ts-1,
                "stopTime": ts+1
                }
        url = base + urllib3.request.urlencode(query)
        data = {
                "tags": msg["alert"]["signature"].replace(" ", "_")
                }
        ret = requests.post(url, data=data, auth=requests.auth.HTTPDigestAuth(MUSER, MPASS))
        try:
            status = json.loads(ret.text)
            if not status["success"]: print(status["text"])
        except:
            pass
    except KeyError as e:
        print(msg)
