# WISE - With Intelligence See Everything

  * https://github.com/aol/moloch/wiki/WISE#wise---with-intelligence-see-everything
  * https://github.com/aol/moloch/tree/master/capture/plugins/wiseService
  * https://github.com/aol/moloch/wiki/Adding-new-WISE-sources
  * https://github.com/aol/moloch/wiki/TaggerFormat

Suppose we have following information - `8.8.8.8` and `1.1.1.1` are both popular public DNS servers. Former belongs to Google and second to Cloudflare. `8.8.4.4` is also a DNS server and belongs to Google. `192.168.10.11`, `192.168.10.12`, `192.168.10.13` and `192.168.10.14` are used by us and correspond to singlehost, buildbox, api box, and current wise box. None of them are DNS servers but we might add some resolvers into this subnet in the future.

Now, suppose we have a bunch of annoying analysts who want to see traffic for DNS servers OR particular organizations, but don't care much for IP addresses and don't want to write compound queries. Maybe they even want to use SPI graph on timeseries aggregations and don't want to write their own aggregators agains elasticsearch. Suppose you want to see traffic between exercise workstations and don't want to write a 1000+ element query that lists all workstation IP addresses with logical OR separator (which would result in quite an inefficient query anyway).

Suppose we have a list of known bad IP addresses, or domains, or JA3 hashes...

## Running wise

 * https://github.com/aol/moloch/wiki/WISE#installation

Start by copying the sample wise config file in the `etc` dir of moloch install root.

```
cd /data/moloch/etc
cp wise.ini.sample wise.ini
```

Running it with default config is as simple as going into `wiseService` folder and executing it with bundled node.

```
cd /data/moloch/wiseService
../bin/node wiseService.js -c ../etc/wise.ini
```

Then modify the `config.ini` to enable wise plugins for capture and viewer.

```
plugins=wise.so
viewerPlugins=wise.js
```

Point them to correct wise server.

```
wiseHost=127.0.0.1
```

And maybe set up additional options. For example, capture will cache all wise results for N seconds (by default 600). And tuple lookups may be too intensive in high bandwidth traffic (proto+srcip+srcport+dstip+dstport unique combos).

```
wiseCacheSecs=60
wiseTcpTupleLookups=true
wiseUdpTupleLookups=true
```

Then restart the capture and viewer instances. Observe logs from each service to ensure that it works.

## Using simple plugins
  
  * https://github.com/aol/moloch/wiki/TaggerFormat
  * https://github.com/aol/moloch/wiki/WISE#File
  * https://github.com/aol/moloch/wiki/WISE#Redis

Coming back to initial problem with nameservers and owners. We can create a file with following content in Moloch tagger format:

```
8.8.8.8;asset=dns
8.8.4.4;asset=dns
1.1.1.1;asset=dns
192.168.10.11;asset=singlehost
192.168.10.12;asset=build
192.168.10.13;asset=api
192.168.10.14;asset=wise
```

Let's create `/tmp/assets.txt` and add this to `wise.ini`

```
[file:iptagger]
file=/tmp/assets.txt
tags=ipwisetagger
type=ip
format=tagger
```

Then reload wise service and look at SPI view. You may need to wait for a bit or reload some services.

## Creating custom fields

While the simple example works, it does not solve our initial problem. We depend on `asset` field that already exists in Moloch database. Some fields, like `tags`, allow for multiple values, but the result would be quite messy when seen under SPI view. And aggregations can become difficult. Luckily, we can create custom fields that can be grouped together under SPI view. And it's difficult to scale if new logical types are added in future. In other words, logical `owner` that is Google or Cloudflare (or us) and `type` which is DNS, are difficult to separate.

Rather, we would like to have our own `custom` field group with sub fields `owner` and `type`. This can be done in multiple ways. See [tagger format](https://github.com/aol/moloch/wiki/TaggerFormat) for more.

### File plugin comments

Custom fields can be prepended to file plugin source file as comments.

```
#field:custom.owner;kind:lotermfield;count:true;friendly:Name;db:custom.owner;help:Traffic owner
#field:custom.type;kind:lotermfield;count:true;friendly:Type;db:custom.type;help:Traffic type
8.8.8.8;custom.owner=google;custom.type=dns
1.1.1.1;custom.owner=cloudflare;custom.type=dns
192.168.10.14;custom.owner=us;custom.type=vagrant
```

### WISE plugin config option

`fields` parameter can be specified when invoking the plugin. Note that newline separates the types.

```
[file:iptagger]
file=/tmp/assets.txt
tags=ipwisetagger
type=ip
format=tagger
fields=field:custom.owner;kind:lotermfield;count:true;friendly:Name;db:custom.owner;help:Traffic owner\nfield:custom.type;kind:lotermfield;count:true;friendly:Type;db:custom.type;help:Traffic type
```

### config.ini

`[custom-fields]` section can be added to main `config.ini`.

```
[custom-fields]
custom.owner=kind:lotermfield;count:true;friendly:Name;db:custom.owner;help:Traffic owner
custom.type=kind:lotermfield;count:true;friendly:Type;db:custom.type;help:Traffic type
```

## Adding those types to Session view

New types will be displayed in SPI view automatically, but will not be reflected in opened Sessions. That has to be configured manually.

```
[custom-views]
custom=title:Totally Custom;require:custom;fields:custom.owner,custom.type
```

## Pulling data from remote sources

Maybe we have multiple capture instances that need to be synced. Or maybe we simply don't want to manage arbitrary files in the system. We could use *Redis* plugin that is nearly identical to *file*. Firstly, let's fire up a docker instance.

```
docker run -tid --name -p 6379:6379 redis
```

And check that it is up and running by setting a key.

```
docker exec redis redis-cli set key "value"
docker exec redis redis-cli get key
```

Create a `wise.ini` section for redis plugin. Assuming that field has already created by any of three methods listed before. Note that `0` at the end of url refers to redis database. If redis is also used as wise cache, then change that to some other number (will be created if does not exist).

```
[redis:ip]
url=redis://127.0.0.1:6379/0
tags=redis
type=ip
format=tagger
```

Reload the wise service as always and set some fields.

```
docker exec redis redis-cli set 208.67.222.222 "208.67.222.222;custom.type=dns;custom.owner=opendns"
docker exec redis redis-cli set 208.67.220.220 "208.67.220.220;custom.type=dns;custom.owner=opendns"
```

Run some test queries against those servers and see if plugin works.

```
for domain in google.com neti.ee berylia.org ; do dig A $domain @208.67.222.222 ; done
```

## Tasks

  * Create three custom groups `ls19`, `cdmcs` and `whatever` of fields. Each group should be defined using a different method (file, fields and custom-fields);
    * Each group should have at least two arbitrary fields (up to you);
    * Using file input plugin, verify that all three groups are present if SPI view;
  * If a session is enriched with custom tag, it should be present in Sessions tab;
  * Using Emerging Threats [IP drop list](http://rules.emergingthreats.net/blockrules/compromised-ips.txt) generate redis plugin entries where `drop.source` field is `emergingthreats`;
    * Entries should expire if not updated in a reasonable time (1 minute should be sufficient for course);
    * ICMP ping should be enough to verify it works **ONLY DO IT IN YOUR DISPOSABLE VM!!!**;

# Writing a WISE plugin

  * https://github.com/aol/moloch/wiki/Adding-new-WISE-sources

WISE has quite a few plugins to integrate popular data sources and threat intelligence feed, but what if we want to do more comprex processing on run lookups agains something more obscure?

## source.useless.js

Let's start off by creating a skeleton of a wise plugin, called `source.useless.js` in `wiseService` folder. It should have a periodic task every N seconds and it should print every X'th looked up item into a console. Start by importing the libraries. Most importantly, our plugin simpley extends `wiseSource.js`.

```javascript
'use strict';

var wiseSource     = require('./wiseSource.js')
  , util           = require('util')
  ;
```

Any additional deps should be added here. For example, if we wanted to interact with filesystem, like load or store data in files, we would need the `fs` module.

```javascript
var wiseSource    = require('./wiseSource.js')
  , util          = require('util')
  , fs            = require('fs')
  ;
```

Then define a new source function that parses `X` and `N` from the config file section `[useless]`. 

```javascript
function UselessSource (api, section) {
  UselessSource.super_.call(this, api, section);

  this.N = api.getConfig(section, "N");
  this.X = api.getConfig(section, "X");
  this.i = 0;

  // Check if variables needed are set, if not return
  if (this.N === undefined) {
    return console.log(this.section, "- Useless N undefined");
  }
  if (this.X === undefined) {
    return console.log(this.section, "- Useless X undefined");
  }

  console.log("N is ", this.N);
  console.log("X is ", this.X);

  // Memory data sources will have this section to load their data
  this.cacheTimeout = -1;

  this.api.addSource("useless", this);
}
```

This module would be loaded unless `N` or `X` are undefined. Then say that our new source inherits methods from `wiseSource`.

```javascript
util.inherits(UselessSource, wiseSource);
```

And finally export it as a new section `useless`.

```javascript
exports.initSource = function(api) {
  var source = new UselessSource(api, "useless");
};
```

This should allow us to call this skeleton of a module by simply defining it in `wise.ini`.

```
[useless]
X = 10
N = 15
```

However, the module does not really do anything other than print `N` and `X` values. Suppose we want to spam these values periodically, we can do that by defining a source variable as function. The output would be seen in `wiseService.js` logs.

```javascript
UselessSource.prototype.spam = function() {
  console.log("N is ", this.N);
  console.log("X is ", this.X);
};
```

In reality, this would be the place for pulling data from external sources, storing our data periodically, printing detailed statistics, etc. It won't kick in, unless we start a periodic routing in `UselessSource` main function.

```javascript
  setInterval(this.spam.bind(this), this.N*1000);
```

We can also replace the `console.log()` statements in `UselessSource` with immediate invocation of this function, as it does exactly the same thing. Doing this is a good idea anyway, as if we were to pull threat intel in this function, we would need to wait N seconds before the data was actually loaded.

```javascript
  setImmediate(this.spam.bind(this));
```

Finally, we would like to do something during wise type lookups. This should be defined as `getItem` function. For example, to implement a domain lookup, we would need something like this.

```javascript
UselessSource.prototype.getDomain = function(domain, cb) {
  console.log(domain);
  cb(null, undefined);
};
```

If we wanted to implement some logic into this function, we would likely need to define whatever variables or data structures in the main `UselessSource` function.

```javascript
function UselessSource (api, section) {
  UselessSource.super_.call(this, api, section);

  this.N = api.getConfig(section, "N");
  this.X = api.getConfig(section, "X");

  this.i = 0;
  ...
```

And then we can use it in lookup function.

```javascript
UselessSource.prototype.getDomain = function(domain, cb) {
  if (this.i%this.X===0) {
    console.log(domain);
  };
  this.i = this.i + 1;
  cb(null, undefined);
};
```

Putting it all together.

```javascript
'use strict';

var wiseSource     = require('./wiseSource.js')
  , util           = require('util')
  ;

function UselessSource (api, section) {
  UselessSource.super_.call(this, api, section);

  this.N = api.getConfig(section, "N");
  this.X = api.getConfig(section, "X");

  // Check if variables needed are set, if not return
  if (this.N === undefined) {
    return console.log(this.section, "- Useless N undefined");
  }
  if (this.X === undefined) {
    return console.log(this.section, "- Useless X undefined");
  }

  setInterval(this.spam.bind(this), this.N*1000);
  setImmediate(this.spam.bind(this));

  // Memory data sources will have this section to load their data
  this.cacheTimeout = -1;

  this.api.addSource("useless", this);
}

util.inherits(UselessSource, wiseSource);

UselessSource.prototype.spam = function() {
  console.log("N is ", this.N);
  console.log("X is ", this.X);
  console.log("i is ", this.i);
};

UselessSource.prototype.getDomain = function(domain, cb) {
  if (this.i%this.X===0) {
    console.log(domain);
  };
  this.i = this.i + 1;
  cb(null, undefined);
};

exports.initSource = function(api) {
  var source = new UselessSource(api, "useless");
};
```
