# WISE - With Intelligence See Everything

see

* https://github.com/aol/moloch/tree/master/capture/plugins/wiseService
* https://github.com/aol/moloch/blob/master/release/config.ini.sample#L60
* https://github.com/aol/moloch/wiki/WISE
* https://github.com/aol/moloch/wiki/Adding-new-WISE-sources
* https://github.com/ccdcoe/CDMCS/blob/master/Moloch/vagrant/singlehost/source.suricata.js
* https://gist.github.com/hillar/f38c73832f7ccdba0379

## Setting up simple asset tagging

### Enable wise in main config file

```
wiseHost=127.0.0.1
plugins=wise.so
viewerPlugins=wise.js
wiseTcpTupleLookups=true
wiseUdpTupleLookups=true
```

### Create asset list

```
#field:custom.name;kind:lotermfield;count:true;friendly:Custom Hostname;db:custom.nameterm;help:Tag known hosts with custom names in separate SPI category;shortcut:0
192.168.10.11;0=me
10.0.2.15;0=me
8.8.8.8;0=googledns
8.8.4.4;0=googledns
```

### create wise config file

```
cd /data/moloch/etc && cp wise.ini.sample wiseService.ini
```

### Add file tagging reference

```
[file:ip]
file=/vagrant/tagger.txt
tags=ipwise
type=ip
format=tagger
```

### Start the wise service

```
cd /data/moloch/wiseService && ../bin/node wiseService.js
```

### Update asset list periodically

```
#!/usr/bin/env python3

import pickle
import ssl
from urllib.request import urlopen

def download(URL=None):
    ssl._create_default_https_context = ssl._create_unverified_context
    resp = urlopen(URL)
    return resp

def field():
    return '#field:LS.host;kind:lotermfield;count:true;friendly:Hostname;db:LS.hostterm;help:Gamenet system name for target;shortcut:0'

def gen(struct):
    yield field()
    for host, ips in struct.items():
        for li in ips:
            for ip in li:
                if ip != "NA":
                    form="%s;0=%s" % (ip, host)
                    yield form

with open("/vagrant/tagger.txt", "w") as f:
    for line in gen(pickle.load(download("https://SITE/assets.pkl"))):
        line = line + "\n"
        f.write(line)
```
