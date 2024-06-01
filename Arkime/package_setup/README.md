# Setting up from deb package

## Install Arkime package

Download arkime package from [the official download page](https://arkime.com/downloads) and install it with your package manager.

```
dpkg -i arkime_5.1.2-1.ubuntu2204_amd64.deb
```

On debian/ubuntu, this will fail.

```
Selecting previously unselected package arkime.
(Reading database ... 111873 files and directories currently installed.)
Preparing to unpack arkime_4.3.1-1_amd64.deb ...
Unpacking arkime (4.3.1-1) ...
dpkg: dependency problems prevent configuration of arkime:
 arkime depends on libwww-perl; however:
  Package libwww-perl is not installed.
 arkime depends on libjson-perl; however:
  Package libjson-perl is not installed.
 arkime depends on libyaml-dev; however:
  Package libyaml-dev is not installed.

dpkg: error processing package arkime (--install):
 dependency problems - leaving unconfigured
Errors were encountered while processing:
 arkime
```

That's okay, it's just missing some dependencies. Dependency manager should take care of it.

```
apt-get -f install
```

Arkime is now installed in `/opt`.

```
cd /opt/arkime
```

```
student@student-linux:/opt/arkime$ ls -lah
total 1.3M
drwxr-xr-x  16 root root 4.0K Jun  7 19:21 .
drwxr-xr-x   4 root root 4.0K Jun  7 19:21 ..
drwxr-xr-x   2 root root 4.0K Jun  7 19:21 assets
drwxr-xr-x   2 root root 4.0K Jun  7 19:21 bin
drwxr-xr-x   2 root root 4.0K Jun  7 19:21 common
drwxr-xr-x   2 root root 4.0K Jun  7 19:21 db
drwxr-xr-x   2 root root 4.0K Jun  7 19:21 etc
drwxr-xr-x   2 root root 4.0K Jun  7 19:21 include
-rwxr-xr-x   1 root root  729 Mar 31 19:45 LICENSE
drwxr-xr-x   2 root root 4.0K Jun  7 19:21 lua
drwxr-xr-x 366 root root  12K Jun  7 19:21 node_modules
drwxr-xr-x   7 root root 4.0K Jun  7 19:21 node-v16.14.2-linux-x64
-rw-r--r--   1 root root 1.2M Mar 31 19:45 NOTICE.txt
-rwxr-xr-x   1 root root 7.7K Mar 31 19:43 package.json
drwxr-xr-x   4 root root 4.0K Jun  7 19:21 parliament
drwxr-xr-x   2 root root 4.0K Jun  7 19:21 parsers
drwxr-xr-x   3 root root 4.0K Jun  7 19:21 plugins
-rwxr-xr-x   1 root root 1.7K Mar 31 19:45 README.txt
drwxr-xr-x   6 root root 4.0K Jun  7 19:21 viewer
drwxr-xr-x   4 root root 4.0K Jun  7 19:21 wiseService
```

## Get elasticsearch up and running

### Using docker

Set up elasticsearch.

```
docker run -ti -d --name arkime-elastic -v elastic_data:/usr/share/elasticsearch/data:rw -p 127.0.0.1:9200:9200 -e "discovery.type=single-node" -e "xpack.security.enabled=false" --restart unless-stopped docker.elastic.co/elasticsearch/elasticsearch:8.13.4
```

Verify that elastic is up and running. You can check logs...

```
docker logs arkime-elastic --follow
```

...or interact with elastic API.

```
student@student-linux:~$ curl -ss http://localhost:9200
{
  "name" : "43194d1deb40",
  "cluster_name" : "docker-cluster",
  "cluster_uuid" : "lWs_x9FMSNKgd3V2AcDipA",
  "version" : {
    "number" : "8.8.1",
    "build_flavor" : "default",
    "build_type" : "docker",
    "build_hash" : "f8edfccba429b6477927a7c1ce1bc6729521305e",
    "build_date" : "2023-06-05T21:32:25.188464208Z",
    "build_snapshot" : false,
    "lucene_version" : "9.6.0",
    "minimum_wire_compatibility_version" : "7.17.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "You Know, for Search"
}
```

Some important endpoints to keep tabs on.

```
/_cat/indices
/_cat/shards
/_cat/health
```


### Using a deb package

```
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.13.4-amd64.deb
dpkg -i elasticsearch-8.13.4-amd64.deb
```

Set the JVM heap size in `/etc/elasticsearch/elasticsearch.yml`

```
-Xms1g
-Xmx1g
```

Proper elasticsearch setup is outside the scope of this training. Elasticsearch now defaults to full TLS with authentication via `xpack` extensions. While arkime can handle this just fine, we'll nevertheless disable it for the training to reduce overhead. Simply set `xpack.security.enabled` to `false` in `/etc/elasticsearch/elasticsearch.yml`.

```
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl start elasticsearch.service
```

```
curl -ss localhost:9200
```

## Initialize elastic database

Before configuring, let's take care of setting up the database. Enter the `db` directory.

```
cd /opt/arkime/db
```

And call the database management script.

```
student@student-linux:/opt/arkime/db$ ./db.pl localhost:9200 init
It is STRONGLY recommended that you stop ALL Arkime captures and viewers before proceeding.  Use 'db.pl http://localhost:9200 backup' to backup db first.

There is 1 elastic search data node, if you expect more please fix first before proceeding.

This is a fresh Arkime install
Erasing
Creating
Finished
```

Verify the elastic indices.

```
student@student-linux:/opt/arkime/db$ curl -ss localhost:9200/_cat/indices
green open arkime_parliament_v50 sKDnv_2_QmGBn38QfYWCbA 1 0  0  0   249b   249b   249b
green open arkime_sequence_v30   9mhbON3rTAq7wu3GdVaGEg 1 0  0  0   249b   249b   249b
green open arkime_queries_v30    ge3G705LSTmktJ2zGsd3Og 1 0  0  0   249b   249b   249b
green open arkime_dstats_v30     nVosaSAtRVK9lhfIPHyOKg 2 0  0  0   498b   498b   498b
green open arkime_fields_v30     HqLqjrc5Q-uxNC_Pb44G1A 1 0 47 17 53.3kb 53.3kb 53.3kb
green open arkime_notifiers_v40  9j3EJ56VSoiix_9o1gevag 1 0  0  0   249b   249b   249b
green open arkime_lookups_v30    hPMoGTAqS6-L-abJygEcHg 1 0  0  0   249b   249b   249b
green open arkime_views_v40      Emu7WT9vRaeUqH8PP2E6Cw 1 0  0  0   249b   249b   249b
green open arkime_users_v30      bEdZVRBZTMWNbCV-y8UpwA 1 0  0  0   249b   249b   249b
green open arkime_files_v30      2BXir-1GTfCFhH4Qd79D7A 2 0  0  0   498b   498b   498b
green open arkime_stats_v30      qHf6qhGMQ2u6e2r2Jj2ubQ 1 0  0  0   249b   249b   249b
green open arkime_hunts_v30      PZHEKoe6RueB_cBlSRgPpw 1 0  0  0   249b   249b   249b
```

## Set up WISE

WISE stands for `With Intelligence See Everything`. It's a nodejs service that complements arkime capture and viewer. While it's non-essential, it should nevertheless be set up first. Capture and Viewer will attempt to connect to WISE if configured to use it. They will fail if WISE is not already up and running.

Firstly, set up the WISE config file.

```
cp /opt/arkime/etc/wise.ini.sample /opt/arkime/etc/wise.ini
```

Edit the config file in `/opt/arkime/etc/wise.ini`. Firstly, enable the `reversedns` module.

```
[reversedns]
ips=10.0.0.0/8
field=asset
```

Secondly, we can create a custom source to enrich some data types. For example, we can define information about IP addresses in a text file to enrich our NDR info. That info can be asset enrichment to translate addresses into human-readable names. Or it can be a threat intel feed to mark on IoC-s.

```
[file:ip]
file=/opt/arkime/etc/ip-data.txt
tags=ipwise
type=ip
format=tagger
```

Then create the corresponding file `/opt/arkime/etc/ip-data.txt`. Note the initial *commented* lines. These are not comments! They define custom fields that are used. WISE is simply a API that capture will query before saving the session in Elasticsearch. Viewer also uses WISE to inject new functionality into viewer code.

**Note that this will not work until custom fields are created by capture.** Go to *cool tricks* section at the end to see how to do that.

```
#field:cdmcs.name;shortcut:0
#field:cdmcs.type;shortcut:1
192.168.56.11;0=local
10.0.2.15;0=local
8.8.8.8;0=google;1=dns
8.8.4.4;0=google;1=dns
1.1.1.1;0=cloudflare;1=dns
66.6.32.31;0=tumblr;1=web
66.6.33.31;0=tumblr;1=web
66.6.33.159;0=tumblr;1=web
```

Go to `wiseService` folder. Since it's a nodejs app, everything needs to be executed from that root path.

```
cd /opt/arkime/wiseService
```

Then test that configuration works by executing WISE on command line.

```
root@setup:/opt/arkime/wiseService# /opt/arkime/bin/node wiseService.js -c /opt/arkime/etc/wise.ini
[[20:03:06.500]] [LOG]   alienvault - No export key defined
[[20:03:06.502]] [LOG]   emergingthreats - No key defined
[[20:03:06.503]] [LOG]   hodiredis - ERROR not loading since no url specified in config file
[[20:03:06.504]] [LOG]   opendns - No key defined
[[20:03:06.504]] [LOG]   passivetotal - No key defined
[[20:03:06.539]] [LOG]   threatq - No export key defined
[[20:03:06.544]] [LOG]   threatstream - No user defined
[[20:03:06.545]] [LOG]   virustotal - No key defined
[[20:03:06.552]] [LOG]   file:ip - Done Loading 8 elements
[[20:03:08.496]] [LOG]   Express server listening on port 8081 in development mode
```

If all seems well, exit the foreground program and set up a systemd service. Add following content to `/etc/systemd/system/arkime-wise.service`.

```
[Unit]
Description=arkime WISE
After=network.target

[Service]
Type=simple
Restart=on-failure
ExecStart=/opt/arkime/bin/node wiseService.js -c /opt/arkime/etc/wise.ini
WorkingDirectory=/opt/arkime/wiseService
SyslogIdentifier=arkime-wise

[Install]
WantedBy=multi-user.target
```

Systemd needs a refresh after units are added or changed.

```
systemctl daemon-reload
```

Then start and enable the service.

```
systemctl enable arkime-wise.service
systemctl start arkime-wise.service
systemctl status arkime-wise.service
```

Observe that output is something like this.

```
● arkime-wise.service - arkime WISE
     Loaded: loaded (/etc/systemd/system/arkime-wise.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2022-06-07 20:11:51 UTC; 3s ago
   Main PID: 8711 (node)
      Tasks: 11 (limit: 4611)
     Memory: 42.0M
     CGroup: /system.slice/arkime-wise.service
             └─8711 /opt/arkime/bin/node wiseService.js -c /opt/arkime/etc/wise.ini

Jun 07 20:11:51 setup arkime-wise[8711]: [[20:11:51.799]] [LOG]   alienvault - No export key defined
Jun 07 20:11:51 setup arkime-wise[8711]: [[20:11:51.801]] [LOG]   emergingthreats - No key defined
Jun 07 20:11:51 setup arkime-wise[8711]: [[20:11:51.803]] [LOG]   hodiredis - ERROR not loading since no url specified in config file
Jun 07 20:11:51 setup arkime-wise[8711]: [[20:11:51.803]] [LOG]   opendns - No key defined
Jun 07 20:11:51 setup arkime-wise[8711]: [[20:11:51.804]] [LOG]   passivetotal - No key defined
Jun 07 20:11:51 setup arkime-wise[8711]: [[20:11:51.836]] [LOG]   threatq - No export key defined
Jun 07 20:11:51 setup arkime-wise[8711]: [[20:11:51.840]] [LOG]   threatstream - No user defined
Jun 07 20:11:51 setup arkime-wise[8711]: [[20:11:51.841]] [LOG]   virustotal - No key defined
Jun 07 20:11:51 setup arkime-wise[8711]: [[20:11:51.848]] [LOG]   file:ip - Done Loading 8 elements
Jun 07 20:11:53 setup arkime-wise[8711]: [[20:11:53.796]] [LOG]   Express server listening on port 8081 in development mode
```

## Set up Capture

Capture is a tcpdump-like program written in C. It writes raw packets into pcap files on disk and stores session metadata in elasticsearch. It also stores the offset of every packet for a session on disk, which will later allow viewer to reconstruct full packet stream whenever a session is expanded.

Firstly, call geoip update script to pull some files. Capture will not start if those files are missing.

```
root@setup:/opt/arkime# /opt/arkime/bin/arkime_update_geo.sh
2022-06-07 20:15:19 URL:https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv [23331/23331] -> "/tmp/tmp.FUDuons64v" [1]
2022-06-07 20:15:19 URL:https://raw.githubusercontent.com/wireshark/wireshark/master/manuf [2004683/2004683] -> "/tmp/tmp.XRkZ70f7VI" [1]
```

Create a folder with correct permissions to store pcap files. If you choose another folder, make sure it's reflected in config.

```
mkdir /opt/arkime/raw
chown nobody:daemon /opt/arkime/raw/
```


All configuration is in `/opt/arkime/etc/config.ini`. That needs to be set up. **Do not add new options at the end of the file**. Arkime supports multi-capture / multi-viewer setup that share a config file. So adding a option at the end means configuring another node section and it would never apply on the default one.

```
cp /opt/arkime/etc/config.ini.sample /opt/arkime/etc/config.ini
```

Replace the placeholder for arkime install path.

```
sed -i "s/ARKIME_INSTALL_DIR/\/opt\/arkime/g" /opt/arkime/etc/config.ini
```

Point arkime to elasticsearch.

`elasticsearch=http://localhost:9200`

Set a **random** passphrase. This is a secret value used to encrypt user passwords in database. So just roll your hands over the keyboard.

`passwordSecret = <somethingveryrandom>`

Insert a semicolon separated list of interfaces to sniff on. Use `ip link show` to find your system interfaces.

`interface=eth0;eth1`

WISE can be set up by importing a capture module and pointing capture to the service.

```
wiseHost=127.0.0.1
```

```
plugins=wise.so
```

Since Arkime v4 the PCAPs written to the disk are automatically gzipped. As a side-effect it's not possible to view the contents of a PCAP file that is currently being written. If you are a low-volume network it might be a while before the PCAP file will reach the maxSize (default 12GB), so for the purposes of this lab we will turn off the compression feature. Add the following statement somewhere in the [default] section of `config.ini`.

```
simpleCompression=none
```

Then test the capture service.

```
/opt/arkime/bin/capture -c /opt/arkime/etc/config.ini
```

Then check the elastic to verify that `arkime_sessions3-*` exists.

```
root@setup:/opt/arkime# curl -ss localhost:9200/_cat/indices
green open arkime_lookups_v30      Xh0RlVK8RGCNosJqQdoM9g 1 0   0  0    226b    226b
green open .geoip_databases        ObOMS7HdSzysFuJ1Ju8jew 1 0  40  0  38.1mb  38.1mb
green open arkime_sequence_v30     0SLIuYNCQ1eFM5NfZLp9Aw 1 0   1  2   3.9kb   3.9kb
green open arkime_users_v30        p4VQhHcuRZKtNs0qL8WQJA 1 0   0  0    226b    226b
green open arkime_queries_v30      0N2EAf0yQDCuwyVtCMhE0A 1 0   0  0    226b    226b
green open arkime_dstats_v30       ozhO1kfRTfyz2Kbrh-EmUA 2 0   3  0  22.5kb  22.5kb
green open arkime_files_v30        BI2dSNYCSY2d506OKWyyfQ 2 0   1  1  11.4kb  11.4kb
green open arkime_fields_v30       x5ZC1MbpTIm1-kESopxkFA 1 0 352 26 161.4kb 161.4kb
green open arkime_stats_v30        Vmn-lc8gTtCiK6Iy6TnfFw 1 0   1  3    22kb    22kb
green open arkime_sessions3-220607 7fjFa85STb6TWwlfzQ3iKw 1 0   1  0  19.6kb  19.6kb
green open arkime_hunts_v30        mD01vypESfmTtQ8pH5MFVQ 1 0   0  0    226b    226b
```

And make sure we have pcap on disk.

```
root@setup:/opt/arkime# ls -lah /opt/arkime/raw/
total 84K
drwxr-xr-x  2 nobody daemon 4.0K Jun  7 20:34 .
drwxr-xr-x 17 root   root   4.0K Jun  7 20:25 ..
-rw-r-----  1 nobody daemon  73K Jun  7 20:34 setup-220607-00000101.pcap
```

Then set up a systemd service.

```
[Unit]
Description=arkime Capture
After=network.target arkime-wise.service

[Service]
Type=simple
Restart=on-failure
ExecStartPre=-/opt/arkime/bin/arkime_config_interfaces.sh -c /opt/arkime/etc/config.ini -n default
ExecStart=/opt/arkime/bin/capture -c /opt/arkime/etc/config.ini
WorkingDirectory=/opt/arkime
LimitCORE=infinity
LimitMEMLOCK=infinity
SyslogIdentifier=arkime-capture

[Install]
WantedBy=multi-user.target
```

Check the service when set up. Just mirror the WISE section for service setup.

```
● arkime-capture.service - arkime Capture
     Loaded: loaded (/etc/systemd/system/arkime-capture.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2022-06-07 20:42:37 UTC; 1s ago
    Process: 9344 ExecStartPre=/opt/arkime/bin/arkime_config_interfaces.sh -c /opt/arkime/etc/config.ini -n default (code=exited, status=0/SUCCESS)
   Main PID: 9388 (capture)
      Tasks: 7 (limit: 4611)
     Memory: 207.1M
     CGroup: /system.slice/arkime-capture.service
             └─9388 /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini

Jun 07 20:42:37 setup arkime-capture[9388]: Jun  7 20:42:37 http.c:389 moloch_http_curlm_check_multi_info(): 1/6 ASYNC 200 http://localhost:9200/arkime_fields/_doc/packets.src 189/157 0ms 76ms
Jun 07 20:42:37 setup arkime-capture[9388]: Jun  7 20:42:37 writer-simple.c:840 writer_simple_init(): INFO: Reseting pcapWriteSize to 262144 since it must be a multiple of 4096
Jun 07 20:42:37 setup arkime-capture[9388]: Jun  7 20:42:37 http.c:389 moloch_http_curlm_check_multi_info(): 4/6 ASYNC 201 http://localhost:9200/arkime_dstats/_doc/setup-511-5 786/154 0ms 38ms
Jun 07 20:42:37 setup arkime-capture[9388]: Jun  7 20:42:37 http.c:389 moloch_http_curlm_check_multi_info(): 3/6 ASYNC 201 http://localhost:9200/arkime_dstats/_doc/setup-1242-60 787/155 0ms 38ms
Jun 07 20:42:37 setup arkime-capture[9388]: Jun  7 20:42:37 http.c:389 moloch_http_curlm_check_multi_info(): 2/6 ASYNC 200 http://localhost:9200/arkime_dstats/_doc/setup-124-600 788/158 0ms 38ms
Jun 07 20:42:37 setup arkime-capture[9388]: Jun  7 20:42:37 http.c:389 moloch_http_curlm_check_multi_info(): 1/6 ASYNC 200 http://localhost:9200/arkime_stats/_doc/setup?version_type=external&version=30 786/150 0ms 50ms
Jun 07 20:42:38 setup arkime-capture[9388]: Jun  7 20:42:38 packet.c:1299 moloch_packet_batch(): Initial Packet = 1654634557 Initial Dropped = 0
Jun 07 20:42:38 setup arkime-capture[9388]: Jun  7 20:42:38 db.c:2070 moloch_db_create_file_full(): Creating file 105 with key >/arkime_files/_doc/setup-105?refresh=true< using >{"num":105, "name":"/opt/arkime/raw/setup-220607-00000105.pcap", "first":1654634557, "node":"set>
Jun 07 20:42:38 setup arkime-capture[9388]: Jun  7 20:42:38 http.c:389 moloch_http_curlm_check_multi_info(): 2/6 ASYNC 200 http://localhost:9200/arkime_sequence/_doc/fn-setup 2/156 0ms 37ms
Jun 07 20:42:38 setup arkime-capture[9388]: Jun  7 20:42:38 http.c:389 moloch_http_curlm_check_multi_info(): 1/6 ASYNC 201 http://localhost:9200/arkime_files/_doc/setup-105?refresh=true 141/167 0ms 61ms
```

Logs can be read in journald.

```
journalctl -u arkime-capture.service --follow --output cat
```

## Set up viewer

Arkime viewer is a nodejs service that provides the hunting interface. 

It shares its config file with capture, meaning most parameters should already be set up if you have capture running. Some parameters are only used by capture, others only by viewer. For example, WISE plugin needs to be loaded with different config parameter than capture. URL, however, is shared with capture.

```
# Semicolon ';' seperated list of viewer plugins to load and the order to load in
viewerPlugins=wise.js
```

Like WISE, everything needs to be executed in `viewer` folder.

```
cd /opt/arkime/viewer
```

Web interface needs a user. We can create one with provided viewer script. Note that if you ever reconfigure `passwordSecret`, then user also needs to be updated as the password is encrypted with that secret.

```
/opt/arkime/bin/node addUser.js -c /opt/arkime/etc/config.ini owl owl owlpass --admin
```

Then test out running the viewer.

```
/opt/arkime/bin/node viewer.js -c /opt/arkime/etc/config.ini
```

And finally set up systemd service.

```
[Unit]
Description=arkime Viewer
After=network.target arkime-wise.service

[Service]
Type=simple
Restart=on-failure
ExecStart=/opt/arkime/bin/node viewer.js -c /opt/arkime/etc/config.ini
WorkingDirectory=/opt/arkime/viewer
SyslogIdentifier=arkime-viewer

[Install]
WantedBy=multi-user.target
```

## Adding JA4+ support

JA3 is a TLS fingerprinting technique that has become an industry standard. It is essentially a MD5 hash of TLS client or server HELLO packet. I.e., before TLS client and server can actually establish encrypted communications, they need to exchange cyper suites in order to agree on common encryption algorithms that both sides support. This is a sequence of numbers, and JA3 is basically just a hash of that sequence.

Since 2023, Google Chrome started randomizing the order in which extensions are issued. This is called [TLS ClientHello Extension Permutation](https://www.stamus-networks.com/blog/ja3-fingerprints-fade-browsers-embrace-tls-extension-randomization), and it effectively killed JA3 fingerprinting. Sequence of these numbers is now random and thus produces a different hash every time.

In order to deal with this problem, NSM tools are migrating to JA4 hashing, which is really a suite of fingerprinting techniques not only for TLS clients and servers, but also for HTTP, SSH, TCP, etc. Among other things, JA4 is also more resilient against randomization. But JA4 has another major issue which prevents open-source tools from simply incorporating it. JA4 for client and QUIC are released under BSD licence, but others are sold with commercial licence instead. [These other fingerprinting techniques, referred to as JA4+, can not be used for monetization](https://github.com/FoxIO-LLC/ja4#licensing), so open-source tools could easily get into trouble by including them.

Arkime gets around that by providing compiled ja4 plugin that can then be set up by the users themselves. It is quite simple, a shared object (`.so`) file needs to be placed into `plugins` folder and then enabled as capture plugin.

* https://github.com/arkime/arkime/releases
* https://arkime.com/settings#ja4plus

## Cont3xt

[Cont3xt](https://arkime.com/cont3xt) is a new tool in the Arkime family. It's been around since version 4 but has been improved in v5. It is a nodejs web application that condenses indicator lookups to a single interface. For example, instead of having different browser tabs open for virustotal, shotad, etc, one simply queries the indicator (domain, IP, hash, email, etc) from cont3xt instead. In the backend, cont3xt queries different services for you and then presents condensed info on a single screen.

* https://arkime.com/cont3xt#install

Note, this guide sets up default cont3xt systemd service which logs to plaintext file under `/opt/arkime/logs` folder. If following this tutorial, that folder might be missing and service would fail. Make sure the folder exists before restarting the service.

## Adding custom fields

Arkime is not limited to fields defined by its creators. You can add your own!

### Overriding geoip

You can override fields in `config.ini` using the `[override-ips]` section. This works per subnet. Note that country is limited only to 2 chars. This is a really useful trick in exercises where networks are simulated anyway. Can also be useful for adding context to internal subnets that are geographically separated.

* https://arkime.com/taggerformat

```
[override-ips]
192.168.56.0/24=tag:private-net;country:BY;rir:SINET;asn:AS0000 This is neat
10.0.2.0/24=tag:private-net;country:CR;rir:SINET;asn:AS0000 This is neat
```

### Adding custom fields

You can define new fields in `config.ini`. Note that this can also be done in WISE plugin setup but is much cleaner in main config file. Very useful for instant asset documentation. If you have a API to pull asset data from, generate some WISE data!

* https://arkime.com/settings#custom-fields

```
[custom-fields]
target.name=kind:lotermfield;count:true;friendly:Name;db:target.name;help:Target name
cdmcs.name=kind:lotermfield;count:true;friendly:Name;db:cdmcs.name;help:Traffic owner
cdmcs.type=kind:lotermfield;count:true;friendly:Type;db:cdmcs.type;help:Traffic type
```

### Making custom fields visible in sessions view

New fields are better when visible for related sessions. Again, this can be done with other (more painful) methods, but this is the cleanest.

* https://arkime.com/settings#custom-views

```
[custom-views]
cdmcs=title:Cyber Defence Monitoring Course;require:cdmcs;fields:cdmcs.name,cdmcs.type
```

### Arkime rules

Arkime can define rules. These are not like suricata rules that apply on PCAP data. Rather, they process metadata and then modify indexed session or allow for custom PCAP handling control flows. A typical use-case is dropping encrypted packets once initial TLS session metadata is built (to save storage space).

* https://arkime.com/rulesformat
* https://arkime.com/rules

In `config.ini` -

```
rulesFiles=/opt/arkime/etc/rules.conf
```

Then individual rules files look like this.

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
```
