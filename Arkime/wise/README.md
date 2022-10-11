# Threat intelligence / encriching the data

Suppose we have following information - `8.8.8.8` and `1.1.1.1` are both popular public DNS servers. Former belongs to Google and second to Cloudflare. `8.8.4.4` is also a DNS server and belongs to Google. `192.168.56.11`, `192.168.56.12`, `192.168.56.13` and `192.168.56.14` are used by us and correspond to singlehost, buildbox, api box, and current wise box. None of them are DNS servers but we might add some resolvers into this subnet in the future.

Now, suppose we have a bunch of annoying analysts who want to see traffic for DNS servers OR particular organizations, but don't care much for IP addresses and don't want to write compound queries. Maybe they even want to use SPI graph on timeseries aggregations and don't want to write their own aggregators agains elasticsearch. Suppose you want to see traffic between exercise workstations and don't want to write a 1000+ element query that lists all workstation IP addresses with logical OR separator (which would result in quite an inefficient query anyway).

Suppose we have a list of known bad IP addresses, or domains, or JA3 hashes...

There are multiple ways to do this, for example:
  * [addTags API endpoint](https://github.com/aol/moloch/wiki/API#addtags)
  * [rule files](https://github.com/aol/moloch/wiki/RulesFormat)
  * [wise](https://github.com/aol/moloch/wiki/WISE#wise---with-intelligence-see-everything)

# API

  * [See API reference](/Arkime/queries#api)

# Rules

  * https://github.com/aol/moloch/wiki/RulesFormat

Simple rules can be defined for moloch-capture in yaml format. Firstly, add a `rulesFiles` directive to `config.ini`. Multiple files can be defined when separated by a semicolon.

```
rulesFiles=/data/moloch/etc/rules1.yaml;/data/moloch/etc/rules2.yaml;...
```

Then create rules in respective files. Multiple rules can be crated in a single file. Rules can be used for filtering traffic or for assigning fields based on query parameters in `fields` section.

```
version: 1
rules:
  - name: "Drop tls"
    when: "fieldSet"
    fields:
      protocols:
      - tls
    ops:
      _maxPacketsToSave: 12
  - name: "Set custom protocol on certain hosts"
    when: "fieldSet"
    fields:
      protocols:
        - http
        - tls
      host.http:
        - testmyids.com
        - self-signed.badssl.com
    ops:
      "tags": "IDStest"
  - name: "Set custom protocol when obsering programming language package downloads"
    when: "fieldSet"
    fields:
      protocols:
        - tls
      host.http:
        - go.googlesource.com
        - files.pythonhosted.org
    ops:
      "protocols": "pkg-management"
```

Note that values given for each field are connected by logical `OR`, so this may not be the most dynamic approach if fine-grained queries are needed.

# Wise

  * https://github.com/aol/moloch/wiki/WISE#wise---with-intelligence-see-everything
  * https://github.com/aol/moloch/tree/master/capture/plugins/wiseService
  * https://github.com/aol/moloch/wiki/Adding-new-WISE-sources
  * https://github.com/aol/moloch/wiki/TaggerFormat

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
192.168.56.11;asset=singlehost
192.168.56.12;asset=build
192.168.56.13;asset=api
192.168.56.14;asset=wise
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
192.168.56.14;custom.owner=us;custom.type=vagrant
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
docker run -tid --name my-redis -p 6379:6379 redis
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

# Tasks

**Debugging following tasks in live capture can be cumbersome, use tcpdump to generate a fresh pcap file and `-r` flag wiht `--reprocess` on moloch-capture to read packets offline.**

  * Create custom groups `cdmcs` and `criticality`;
    * `criticality` should have a field `level` with possible values `low`, `medium` and `high`;
    * `cdmcs` can contain any field chosen by you;
    * All custom fields should show up on opened session, if present;
    * Use at least two different field creation methods;
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

### Task

 * Implement the `source.useless.js` plugin;
 * Add `getIp` and `getTuple` functions;
  * `console.log` every Z'th query for those field types;
    * `Z` should be a custom configuration parameter added by you;

## making it somewhat useful

Now we have a useless skeleton of a wise plugin. Suppose we want to create a simple IP lookup utility, similar to file and redis example in the first section, and we have input data in following format:

```json
[
  {
    "ip": "8.8.8.8",
    "owner": "google",
    "type": "dns"
  },
  {
    "ip": "192.168.56.14",
    "owner": "me",
    "type": "vagrant"
  }
]
```

Start by copying the **source.useless.js** to **source.useful.js**, then replace all `Useless` occurrences with `SomewhatUseful` and lowercase `useless` occurrences with `useful`. **Save it as a new source file, do not extend the last one!** Also, throw away everything except bare minimum. New template should look like this.

```javascript
'use strict';

var wiseSource     = require('./wiseSource.js')
  , util           = require('util')
  ;

function SomewhatUsefulSource(api, section) {
  SomewhatUsefulSource.super_.call(this, api, section);

  // Memory data sources will have this section to load their data
  this.cacheTimeout = -1;

  this.api.addSource("useful", this);
  console.log("useful loaded");
}

util.inherits(SomewhatUsefulSource, wiseSource);

SomewhatUsefulSource.prototype.getIp = function(ip, cb) {
  cb(null, undefined);
};

exports.initSource = function(api) {
  var source = new SomewhatUsefulSource(api, "useful");
};
```

As before, we should define any new fields that we want to add. This should be none in `SomewhatUsefulSource` function.

```javascript
  this.owner  = this.api.addField("field:useful.owner;db:useful.owner;kind:lotermfield;friendly:Owner;help:I can haz wise field;count:false");
  this.type   = this.api.addField("field:useful.type;db:useful.type;kind:lotermfield;friendly:Type;help:I can haz another wise field;count:false");
```

As an exercise, we are going to create a plugin that simply keeps all data in memory and periodically updates it. For that, we need to import hashtable package for storing the data.

```javascript
  HashTable     = require('hashtable'),
```

And we should instantiate one in the `SomewhatUsefulSource` function.

```javascript
  this.data = new HashTable();
```

Empty container is empty. Let's write a function to fill it. In reality, this data should be pulled via some IO reader, but that's not really important while trying to figure out WISE-specific nuances.

```javascript
SomewhatUsefulSource.prototype.load = function() {
  var self = this;
  this.data.clear();

  var staticData = [
    {
      ip: "8.8.8.8",
      owner: "google",
      type: "dns"
    },
    {
      ip: "192.168.56.14",
      owner: "me",
      type: "vagrant"
    }
  ];

  i = 0;
  staticData.forEach(function(object){
    var encodedOwner  = wiseSource.encode(self.owner, object.owner);
    var encodedType   = wiseSource.encode(self.type, object.type);
    var encoded       = Buffer.concat([
      encodedOwner,
      encodedType
    ]);
    self.data.put(object.ip, {num: 2, buffer: encoded});
    i++;
  });
  console.log("useful loaded", i, "items");
};
```

So, we are looping through a data structure and filling a hashtable with key-value pairs. Fairly straightforward. But what's the deal with buffers? Well, remember that useless example IP address lookup function wasn't actually looking anything up, but simply returned `undefined` value for all queries. Instead, WISE expects a very specific object structure to be returned. The actual data must be encoded into a binary [buffer](https://nodejs.org/api/buffer.html#buffer_buffer). `num` key signifys the number of items that are encoded into the blob. We have two fields `owner` and `type`. **If this number does not match the actual count of concatenated items, than bad stuff happens.** Look at `moloch-capture` logs for callback errors. Note that `wiseSource.encode` function can actually take any even number of arguments if multiple fields are added. Odd numbered argument is field definition while even argument is the actual data. This example simply illustrates how multiple buffers can be added together via `Buffer.concat` method, and can easily be re-written to omit the concatenation.


```javascript
    var encoded  = wiseSource.encode(
                                      self.owner, object.owner, 
                                      self.type,  object.type,
                                      );
    this.data.put(object.ip, {num: 2, buffer: encoded});
```

**This is just an example of alternative way for implementing the last snippet**. In other words, this spippet is equal to this section:

```javascript
    var encodedOwner  = wiseSource.encode(self.owner, object.owner);
    var encodedType   = wiseSource.encode(self.type, object.type);
    var encoded       = Buffer.concat([
      encodedOwner,
      encodedType
    ]);
    self.data.put(object.ip, {num: 2, buffer: encoded});
```

Concatenation method can be useful if your intel feed has a variable number of possible values, as incorrect `num` value will break your buffer callbacks. For example, if we know the `owner` of IP addres, but not `type`, yet still want to handle both cases with same plugin. 

Regardeless of method, our function will be useless if not invoked **main function**.

```javascript
  setImmediate(this.load.bind(this));
```

Finally, we simply need to implement a proper lookup.

```javascript
SomewhatUsefulSource.prototype.getIp = function(ip, cb) {
  cb(null, this.data.get(ip));
};
```

Note that this simply looks up for previously encoded values. We could implement the encoding logic in lookup function as well and drop the `this.data` variable and `hashtable` package altogether. **Again, this is simply an alternative method for implementing the prior snipped and it will break if staticData variable is not created in our main function**.

```javascript
SomewhatUsefulSource.prototype.getIp = function(ip, cb) {
  this.staticData.forEach(function(object){
    if (object.ip===ip) {
      return cb(null, wiseSource.encode( self.owner, object.owner, self.type, object.type));
    };
  });
  cb(null, unknown);
};
```

This approach would be horribly inefficient as we would need to loop our entire data structure and encode values on positive match upon every single IP addres lookup, which can happen for thousands of times per second (on moderate traffic). Still, example stands in case we wanted to run lookups against external data source, as opposed to keeping everything in process memory and updating periodically.

Finally, while SPI view should pick up any new fields quite easily, we do need to define any additional Sessions view sections manually in our main function. Wise will essentially inject this code into the viewer.

```javascript
  this.api.addView("useful-view",
    "if (session.useful)\n" +
    "  div.sessionDetailMeta.bold Useful\n" +
    "  dl.sessionDetailMeta\n" +
    "    +arrayList(session.useful, 'owner', 'Owner', 'useful.owner')\n"
  );
```

### Tasks

Before getting started:
  * If your testing pcaps have truncated data, you can tell moloch to ingore it with `readTruncatedPackets=true` in main `config.ini`. 
  * Tasks should be achievable by following the snippets and with minimal help from google, only API usage and variable creation, so no fancy stuff here;
  * **Advanced** tasks are for those who have prior JavaScript/nodejs experience, basic scripting skill and basic understanding about sync/async/callbacks expected;
  * Final **brainteaser** is for very advanced users who find basic plugin writing trivial, creativity and basic programming skill expected.

Todo:
  * Implement the `source.useful.js`, read the sections not to mix up important snippets with alternative examples;
  * SomewhatUsefulSource is still pretty useless as data is pretty much hardcoded;
    * Load data periodically from a json file instead;
      * User should be able to configure the file location;
    * **Advanced** Load data from a web server instead;
  * Sessions view only shows `owner` field, but it should also show `type`;
  * Add a new field into the JSON data structure (be creative), verify that this field appears in all relevant sessions;
    * **Advanced** Make that field non mandatory. For example, our vagrant box could also have a field `bigbrother` that is missing from `8.8.8.8`, but that should not break your buffer!
  * **Brainteaser** Both source and destination IP-s are looked up, but directionality does not reflect in returned field. Fix that!
    * Investigate `getTuple` function if working on it.

## Getting fancy

Last example is somewhat useful, but we did not really do anything that we could not implement via built-in plugins. This example enteres all observed domains into a [bloom filter](https://github.com/ccdcoe/CDMCS/blob/master/SDM/go-jupyter/016-bloom.ipynb). Going into probabolistic data structures is outside the scope of this section, but it essentially allows us to make reasonably precise estimations on weather we have previously seen something while using a few kilobytes of memory.

```javascript
'use strict';

var wiseSource     = require('./wiseSource.js')
  , util           = require('util')
  , bloom          = require('bloomfilter')
  ;

//////////////////////////////////////////////////////////////////////////////////
function BloomSource (api, section) {
  BloomSource.super_.call(this, api, section);

  this.bits = api.getConfig(section, "bits");
  this.fn = api.getConfig(section, "functions");
  this.tagval = api.getConfig(section, "tag");

  // Check if variables needed are set, if not return
  if (this.bits === undefined) {
    return console.log(this.section, "- Bloom filter bits undefined");
  }
  if (this.fn === undefined) {
    return console.log(this.section, "- Bloom filter hash functions undefined");
  }
  if (this.tag === undefined) {
    this.tab == "bloom";
  }

  this.dns = new bloom.BloomFilter(
    this.bits, // number of bits to allocate.
    this.fn    // number of hash functions.
  );

  this.tagsField = this.api.addField("field:tags");

  // Memory data sources will have this section to load their data
  this.cacheTimeout = -1;
  //setImmediate(this.load.bind(this));
  //setInterval(this.load.bind(this), 5*60*1000);

  // Add the source as available
  this.api.addSource("bloom", this);
}
util.inherits(BloomSource, wiseSource);
//////////////////////////////////////////////////////////////////////////////////
BloomSource.prototype.getDomain = function(domain, cb) {
  if (!this.dns.test(domain)) {
    this.dns.add(domain);
    return cb(null, {num: 1, buffer: wiseSource.encode(this.tagsField, this.tagval)});
  }
  cb(null, undefined);
};
//////////////////////////////////////////////////////////////////////////////////
exports.initSource = function(api) {
  var source = new BloomSource(api, "bloom");
};
```

Furthermore, [this badly written plugin](https://github.com/markuskont/moloch/blob/master/wiseService/source.ls19.js) was used to tag all traffic for LS19 exercise.

### Tasks

 * Implement the bloom filter example; 
  * How long does bloom filter keep marking new sessions? Explain why!
 * Download `ipmap-04.15.json` from class web server;
  * Implement `source.ls19.js` so that data is loaded from that json file;
  * Test it against exercise pcaps, make sure that `ls19` and `workstation` data is in the indexed sessions;
