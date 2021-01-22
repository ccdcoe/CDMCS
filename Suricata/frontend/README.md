# Web interfaces

This section assumes that student is familiar with:
* Suricata on CLI, configuring it, using rulesets and parsing or replaying PCAP files;
* Getting Elastic up and running with docker, interacting with `/_cat` and `_search` API endpoints;
* Shipping logs to elastic using filebeat or `_bulk` API scripts;

## Evebox

EveBox is a simple web application developed mainly by Jason Ish, one of OISF core developers. It is a lightweight and simple tool. Nevertheless, the interface is intuitive and provides a very good threat hunting interface out of the box. Allowing you to start exploring EVE messages with almost no setup needed. Of course, it's nowhere near as dynamic as Kibana, as it does not leave much room for customizing the interface. But core experience is already quite streamlined.

Most importantly, EveBox allows you to do *flow correlation*. Multiple EVE messages might be triggered for same flow. For example, a HTTP connection could trigger `alert`, `http`, `fileinfo`, and `flow` entry for same connection. Each message contains a `flow_id` that can be used to time them together. And EveBox supports pivoting from those values.

Like filebeat, EveBox is a Go binary. Meaning, no external dependencies. So again, the easiest way to get started is to download latest compiled version and execute it on command line.

```
wget https://evebox.org/files/development/evebox-latest-linux-x64.zip
unzip evebox-latest-linux-x64.zip
cd evebox-latest-linux-x64
./evebox --help
```

While it has a config file and many options, we don't really need much for getting started. Important things can be passed as CLI flags. It uses subcommands, with `server` being the important one we need.

```
evebox server --help
```

Explore the help. Important parameters are `--host`, as the new default is to bind to localhost. Not ideal when running it on VM and you need to connect externally. Others are `--elasticsearch` and `--index`.

```
./evebox server --host 0.0.0.0 --elasticsearch http://localhost:9200 --index filebeat
```

**Important!** If you have some data but certain tables in EveBox are empty, then you likely did not set proper logstash-style template. [This was explained in log shipping section](/Suricata/elastic-log-shipping). Assuming you have Elasticsearch in docker container that was created with `--rm`, then stop that container (removes all data), create new one, set logstash template with `curl -XPUT` and re-parse your PCAP (assuming filebeat is running).

Alternatively, you can also use `curl -XDELETE` to drop all Suricata indices. Mappings cannot be updated once created. So we need to delete old data and re-create it.

If all IP addrs, signatures, etc are present, then **ignore this section**.

## Kibana

Kibana is part of Elastic stack and a swiss army knife for exploring Elastic data. Unlike EveBox that was written for once specific purpose. Easiest way to get up and running is by downloading the package. Not a single binary like EveBox, but bundles everything needed.

**Important!** Kibana is part of Elastic stack. All connected elements must be the same version. Also applies to minor versions. Make sure that kibana package version is same as Elasticsearch. Otherwise, it is liable to simply error when connecting with elastic.

```
wget https://artifacts.elastic.co/downloads/kibana/kibana-oss-7.10.2-linux-x86_64.tar.gz
tar -xzf kibana-oss-7.10.2-linux-x86_64.tar.gz
cd kibana-7.10.2-linux-x86_64/
```

**`--allow-root`** is for sure a bad idea. It only exists because this is a course setup very far removed from anything resembling production. Anyway, these are settings you would otherwise see in `kibana.yml`. But spinning it up on CLI is actually as easy as with EveBox.

```
./bin/kibana --allow-root --elasticsearch http://localhost:9200 --host 0.0.0.0
```
