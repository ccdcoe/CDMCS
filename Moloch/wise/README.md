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
