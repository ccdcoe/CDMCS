#!/usr/bin/env python3

import time
from datetime import datetime, tzinfo, timezone
import urllib3, requests
import json
import argparse
import sys, signal
import types
import socket

import redis
from kafka import KafkaConsumer

import asyncio
import concurrent.futures
import functools

class Alert():
    def __init__(self, eve, **kwargs):
        try:
            self.proto  =   eve["proto"]
            self.sip    =   normalizeIP6(eve["src_ip"])
            self.dip    =   normalizeIP6(eve["dest_ip"])
            self.sprt   =   eve["src_port"]
            self.dprt   =   eve["dest_port"]
        except Exception as e:
            raise e

        self.tz_offset_hours    =   kwargs.get("tz_offset_hours", 0)
        self.ts                 =   self.rfc3339toEpoch(eve["timestamp"])

        if "alert" in eve:
            self.sig    =   self.format(eve["alert"]["signature"])
            self.sig_id =   int(eve["alert"]["signature_id"])
            self.sev    =   int(eve["alert"]["severity"])
        else:
            raise KeyError

        self.window = kwargs.get("window", 1)

    def format(self, tag):
        chars = [" ", "-", ",", "."]
        for c in chars:
            tag = tag.replace(c, "_")
        return tag.lower()

    def rfc3339toEpoch(self, ts):
        ts = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z')
        return int(time.mktime(ts.timetuple())) + (3600*self.tz_offset_hours)

    def Query(self):
        return {
                "expression": self.Expression(),
                "startTime": self.ts - self.window,
                "stopTime": self.ts + self.window 
                }

    def QueryEncode(self): return urllib3.request.urlencode(self.Query())
    def Expression(self): return "( ip.src = %s && port.src = %s && ip.dst = %s && port.dst = %s ) || ( ip.src = %s && port.src = %s && ip.dst = %s && port.dst = %s )" % ( self.FourTuple() + self.FlipFourTuple() )
    def Tags(self): return { "tags": ','.join([ self.sig, "suricata", self.TagSeverity() ]) }
    def FourTuple(self): return (self.sip, self.sprt, self.dip, self.dprt)
    def FiveTuple(self): return (self.sip, self.sprt, self.dip, self.dprt, self.proto)
    def FlipFourTuple(self): return (self.dip, self.dprt, self.sip, self.sprt)
    def FlipFiveTuple(self): return (self.dip, self.dprt, self.sip, self.sprt, self.proto)
    def GetTSdiff(self): return int(time.time()) - self.ts
    def GetTSstring(self): return datetime.fromtimestamp(self.ts).strftime('%Y-%m-%d %H:%M:%S')
    def GetURL(self, api): return api + self.QueryEncode()
    def TagSeverity(self): return "sev_" + str(self.sev)

class Tagger():
    def __init__(self, stream, **kwargs):
        self.host   =   kwargs.get("host",      "locahost")
        self.port   =   kwargs.get("port",      8005)
        self.user   =   kwargs.get("user",      "vagrant")
        self.passwd =   kwargs.get("passwd",    "vagrant")

        self.delay              =   kwargs.get("delay",     60*15)
        self.rate_ms            =   kwargs.get("rate_ms",   1000)
        self.lastflush          =   time.time()
        self.lastTS             =   None
        self.tz_offset_hours    =   kwargs.get("tz_offset_hours", 3)

        if self.tz_offset_hours > 11 or self.tz_offset_hours < -11: raise ValueError

        self.direct     =   kwargs.get("direct",    True)
        self.async      =   kwargs.get("async",     True)
        self.workers    =   kwargs.get("workers",   20)
        self.debug      =   kwargs.get("debug",     False)

        if isGenerator(stream):
            self.stream = stream
        else:
            raise ValueError

        self.api        = "http://%s:%s/addTags?" % (self.host, self.port)
        self.alerts     = []
        self.run        = True
        self.success    = 0

    def Stream(self):
        for msg in self.stream:
            try:
                m = Alert(msg, tz_offset_hours=self.tz_offset_hours)
                self.alerts.append(m)
                diff = m.GetTSdiff()
                if not self.shouldFlush(diff): 
                    sleep = self.delay - diff
                    time.sleep(sleep)
                if len(self.alerts) == self.workers:
                    if self.debug: self.lastTS = self.alerts[-1].GetTSstring()
                    loop = asyncio.get_event_loop()
                    loop.run_until_complete(self.AsyncFlush())
                    #if self.debug and self.lastTS: print("last alert from:", self.lastTS)
            except Exception as e:
                if self.debug: print(e)
            if not self.run: break

        if len(self.alerts) > 0:
            if self.debug: print("flushing tail")
            loop = asyncio.get_event_loop()
            loop.run_until_complete(self.AsyncFlush())
        return self.success

    async def AsyncFlush(self):
        start = int(time.time() * 1000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            loop = asyncio.get_event_loop()
            futures = [ loop.run_in_executor( executor, functools.partial(requests.post, alert.GetURL(self.api), data=alert.Tags(), auth=requests.auth.HTTPDigestAuth(self.user, self.passwd)) ) for alert in self.alerts ]

            success = 0
            for resp in await asyncio.gather(*futures):
                try:
                    s = json.loads(resp.text)
                    if s["success"]: success += 1
                except Exception as e:
                    if self.debug: print(e, ":", resp)

            if self.debug: print("flushed", len(self.alerts), "success:", success, "last alert from:", self.lastTS)
        took = int(time.time() * 1000) - start
        if took < self.rate_ms: time.sleep((self.rate_ms / 1000) - (took / 1000))
        self.alerts = []

    def SyncFlush(self):
        print("flushing", len(self.alerts), "alerts")
        for alert in self.alerts:
            ret = self.Post(alert)
            if self.debug: print(ret.text)
        print("done")
        self.lastflush = time.time()
        self.alerts = []
        return self

    def Post(self, alert, diff):
        url = self.api + alert.QueryEncode()
        if self.debug: print(diff, url)
        ret = requests.post(url, data=alert.Tags(), auth=requests.auth.HTTPDigestAuth(self.user, self.passwd))
        try:
            status = json.loads(ret.text)
            if not status["success"] and self.debug: 
                print(status["text"])
            else:
                self.success += 1
        except Exception as e:
            print(e)
        return ret

    def GetSuccessful(self): return self.success
    def timeDiff(self): return True if int(time.time() - self.lastflush) > self.interval else False
    def shouldFlush(self, diff): return True if diff > self.delay else False

class RedisHandler():
    def __init__(self, **kwargs):
        self.host   = kwargs.get("host", "localhost")
        self.port   = kwargs.get("port", 6379)
        self.db     = kwargs.get("db", 0)

        self.topic  = kwargs.get("topic", "suricata")

        self.modes  = ["range", "pop", "sub"]
        self.mode   = kwargs.get("mode", self.modes[0])
        if self.mode not in self.modes: return "Requested mode not supported"

        try:
            self.conn   = redis.Redis(host=self.host, port=self.port, db=self.db)
        except Exception as e:
            return e

        self.run = True
        self.debug = kwargs.get("debug", False)

        self.jsonerrors = 0
        self.count = 0
        self.keyerrors = 0

        signal.signal(signal.SIGINT, self.Exit)
        signal.signal(signal.SIGTERM, self.Exit)

    def Run(self):
        return self.Pop() if self.mode == "pop" else self.Pull()

    def Exit(self, signum, frame):
        print("Caught", signum)
        self.run = False
        return

    def Pull(self):
        for msg in self.conn.lrange(self.topic, 0, -1):
            try:
                msg = self.json2dict(msg)
                yield msg if msg["event_type"] == "alert" else next
                self.count += 1
            except Exception as e:
                self.jsonerrors += 1
                if self.debug: print(e)
            if not self.run: break
        return self

    def Pop(self):
        while self.run:
            msg = self.conn.blpop(self.topic, timeout=1)
            if msg:
                try:
                    msg = self.json2dict(msg[1])
                    yield msg if msg and msg["event_type"] == "alert" else next
                    self.count += 1
                except Exception as e:
                    self.jsonerrors += 1
                    if self.debug: print(e)
            time.sleep(0.001)
        return self

    def json2dict(self, msg): return json.loads(msg.decode())
    def JSONerrCount(self): return self.jsonerrors
    def Count(self): return self.count

class KafkaHandler():
    def __init__(self, **kwargs):
        self.hosts      =   kwargs.get("hosts", "localhost:9092")
        self.topic      =   kwargs.get("topic", "test")
        self.group_id   =   kwargs.get("group_id", None)
        self.timeout    =   kwargs.get("timeout", 1000*10)

        self.debug      =   kwargs.get("debug", False)

        try:
            self.consumer = KafkaConsumer( self.topic, group_id=self.group_id, bootstrap_servers=self.hosts, consumer_timeout_ms=self.timeout)
            if self.debug: print("initiated kafka consumer")
        except Exception as e:
            print(e)
            return None

        self.run    = True
        self.count  = 0
        self.errors = 0
        self.last   = 0

        signal.signal(signal.SIGINT, self.Exit)
        signal.signal(signal.SIGTERM, self.Exit)

    def Exit(self, signum, frame):
        print("Caught", signum)
        self.run = False
        return

    def Consume(self):
        self.consumer.subscribe([self.topic])
        print("starting consumer")
        for msg in self.consumer:
            try:
                yield json.loads(msg.value)
                self.count += 1
                self.last = msg.offset
            except Exception as e:
                self.errors += 1
                if self.debug: print(e)

            if not self.run:
                print("breaking")
                break

        self.consumer.commit()
        self.consumer.close()
        print("done last offset was", self.last)

        return self

    def Run(self): return self.Consume()
    def Count(self): return self.count
    def JSONerrCount(self): return self.errors

class FileHandler():
    def __init__(self):
        self.path   =   kwargs.get("path", None)
        self.run    =   True

        signal.signal(signal.SIGINT, self.Exit)
        signal.signal(signal.SIGTERM, self.Exit)

    def Run(self):
        with open(self.file, "r") as f:
            for line in f:
                yield json.loads(line.rstrip())
                if not self.run: break

    def Exit(self, signum, frame):
        print("Caught", signum)
        self.run = False
        return

def isGenerator(obj):
    return True if isinstance(obj, types.GeneratorType) else False

def normalizeIP6(addr):
	try:
		internal = socket.inet_pton(socket.AF_INET6, addr)
		return socket.inet_ntop(socket.AF_INET6, internal)
	except socket.error:
		return addr

def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-D',   '--debug',      action='store_true',    default=False)
    parser.add_argument('-d',   '--delay',      default=10,             type=int)
    parser.add_argument('-w',   '--workers',    default=100,            type=int)
    parser.add_argument('-r',   '--rate',       default=1000,           type=int)
    parser.add_argument('-tz',  '--timezone',   default=3,              type=int)
    parser.add_argument('-m',   '--mode',       default='redisListRange')
    parser.add_argument('-s',   '--src',        default="localhost")
    parser.add_argument('-t',   '--topic',      default="suricata-alert")
    parser.add_argument('-mh',  '--moloHost',   default="localhost")
    parser.add_argument('-mp',  '--moloPort',   default=8005)
    parser.add_argument('-mu',  '--moloUser',   default="vagrant")
    parser.add_argument('-mpw', '--moloPword',  default="vagrant")
    return parser.parse_args()

ARGS = arguments()
MODES = ['redisListRange', 'redisListPop', 'kafka', 'file']

if __name__ == "__main__":
    if ARGS.mode == MODES[0]:
        stream = RedisHandler(host=ARGS.src, mode="range", debug=ARGS.debug, topic=ARGS.topic)
    elif ARGS.mode == MODES[1]:
        stream = RedisHandler(host=ARGS.src, mode="pop", debug=ARGS.debug, topic=ARGS.topic)
    elif ARGS.mode == MODES[2]:
        stream = KafkaHandler(hosts=ARGS.src, debug=ARGS.debug, topic=ARGS.topic, group_id="ls18-tagger")
    elif ARGS.mode  == MODES[3]:
        stream = FileHandler(path=ARGS.src)
    else:
        print(ARGS.mode, "mode not supported or not yet implemented, should be one of", MODES)
        sys.exit(1)

    t = Tagger(
        stream.Run(), 
        host=ARGS.moloHost, 
        port=ARGS.moloPort, 
        debug=ARGS.debug, 
        user=ARGS.moloUser, 
        passwd=ARGS.moloPword, 
        workers=ARGS.workers, 
        rate_ms=ARGS.rate,
        tz_offset_hours=ARGS.timezone,
        delay=ARGS.delay
    )
    t.Stream()
