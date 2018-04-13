#!/usr/bin/env python3

import redis
import time
from datetime import datetime
import urllib3, requests
import json
import argparse
import sys, signal
import types

class Alert():
    def __init__(self, eve):
        try:
            self.proto  = eve["app_proto"]
            self.sip    = eve["src_ip"]
            self.dip    = eve["dest_ip"]
            self.sprt   = eve["src_port"]
            self.dprt   = eve["dest_port"]
        except KeyError as e:
            return e

        self.ts     = self.rfc3339toEpoch(eve["timestamp"])

        if "alert" in eve:
            self.sig    = self.format(eve["alert"]["signature"])
            self.sig_id = eve["alert"]["signature_id"]
        else:
            return

        self.window = 1

    def format(self, tag):
        chars = [" ", "-", ",", "."]
        for c in chars:
            tag = tag.replace(c, "_")
        return tag.lower()

    def rfc3339toEpoch(self, ts):
        ts = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z')
        # NOTE! Fix teh timezone hack!!!
        return int(time.mktime(ts.timetuple())) + 10800

    def expression(self):
        return "ip.src = %s && port.src = %s && ip.dst = %s && port.dst = %s" % self.FourTuple()

    def Query(self):
        return {
                "expression": self.expression(),
                "startTime": self.ts - self.window,
                "stopTime": self.ts + self.window 
                }

    def QueryEncode(self):
        return urllib3.request.urlencode(self.Query())

    def Tags(self):
        return { "tags": self.sig }

    def FourTuple(self):
        return (self.sip, self.sprt, self.dip, self.dprt)

    def FiveTuple(self):
        return (self.sip, self.sprt, self.dip, self.dprt, self.proto)

    def FlipFourTuple(self):
        return (self.dip, self.dprt, self.sip, self.sprt)

    def FlipFiveTuple(self):
        return (self.dip, self.dprt, self.sip, self.sprt, self.proto)

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

    def json2dict(self, msg):
        return json.loads(msg.decode())

    def JSONerrCount(self):
        return self.jsonerrors

    def Count(self):
        return self.count

class Tagger():
    def __init__(self, stream, **kwargs):
        self.host   = kwargs.get("host", "locahost")
        self.port   = kwargs.get("port", 8005)
        self.user   = kwargs.get("user", "vagrant")
        self.passwd = kwargs.get("passwd", "vagrant")
        self.direct = kwargs.get("direct", False)

        self.maxmsgs    = kwargs.get("maxmsgs", 10000)
        self.interval   = kwargs.get("interval", 120)
        self.lastflush  = time.time()

        self.debug = kwargs.get("debug", False)

        if isGenerator(stream):
            self.stream = stream
        else:
            return None
        
        self.api        = "http://%s:%s/addTags?" % (self.host, self.port)
        self.alerts     = []
        self.run        = True
        self.success    = 0

    def Stream(self):
        for msg in self.stream:
            if self.direct:
                self.Post(Alert(msg))
            else:
                self.Add(msg)
                if len(self.alerts) == self.maxmsgs or self.timeDiff(): self.Flush()

            if not self.run: break
        if not self.direct: self.Flush()
        return self.success

    def Add(self, msg):
        return self.alerts.append(Alert(msg))

    def timeDiff(self):
        return True if int(time.time() - self.lastflush) > self.interval else False

    def Flush(self):
        print("flushing", len(self.alerts), "alerts")
        for alert in self.alerts:
            ret = self.Post(alert)
        self.lastflush = time.time()
        self.alerts = []
        return self

    def Post(self, alert):
        url = self.api + alert.QueryEncode()
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

    def GetSuccessful(self):
        return self.success

def isGenerator(obj):
    return True if isinstance(obj, types.GeneratorType) else False

def simple():
    for msg in stream.Run():
        msg = Alert(msg)
        query = msg.QueryEncode()
        data = msg.Tags()
        url = BASE + query
        if DEBUG: print(url)
        ret = requests.post(url, data=data, auth=requests.auth.HTTPDigestAuth(MUSER, MPASS))
        try:
            status = json.loads(ret.text)
            if not status["success"]: print(status["text"])
            if DEBUG: print(status)
        except Exception as e:
            if DEBUG: print(ret.text)

def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-D', '--debug', action='store_true', default=False)
    parser.add_argument('-m', '--mode', default='redisListRange')
    parser.add_argument('-d', '--direct', action='store_true', default=False)
    parser.add_argument('-i', '--interval', default=60, type=int)
    return parser.parse_args()

ARGS = arguments()

MODES = ['redisListRange', 'redisListPop',]
MHOST="192.168.10.11"
ALERTSRC=MHOST

#DEBUG=ARGS.debug
MODE=ARGS.mode

# to be deprecated
MUSER="vagrant"
MPASS="vagrant"
CHAN="suricata"
MPORT=8005
BASE="http://%s:%s/addTags?" % (MHOST, MPORT)

if __name__ == "__main__":
    if MODE == "redisListRange":
        stream = RedisHandler(host=ALERTSRC, mode="range", debug=ARGS.debug)
    elif MODE == "redisListPop":
        stream = RedisHandler(host=ALERTSRC, mode="pop", debug=ARGS.debug)
    else:
        print(MODE, "mode not supported or not yet implemented, should be one of", MODES)
        sys.exit(1)

    t = Tagger(stream.Run(), host=MHOST, maxmsgs=10000, direct=ARGS.direct, interval=ARGS.interval, debug=ARGS.debug)
    print("Done pulling", stream.Count(), ", successful addTags responses:", t.Stream(), ", messages errors:", stream.JSONerrCount())
