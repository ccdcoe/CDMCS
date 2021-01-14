# rulesets

This section **does not** assume any knowledge about Suricata YAML configuration. Some references to it will be made. But student should be able to repeat all examples without touching the configuration file.

However, the student should be familiar with:
* Using Suricata with CLI flags (`-S`, `-l`, `-r`, `--af-packet=$IFACE`);
* Parsing offline PCAP files / simple traffic replay;
* Rule file, loading that rule file with `-S`;
* Exploring `eve.json` using `jq`;

## Rule sources

* https://raw.githubusercontent.com/OISF/suricata-intel-index/master/index.yaml

```
curl -ss https://raw.githubusercontent.com/OISF/suricata-intel-index/master/index.yaml | yq '.sources | .[] | .url'
```

## Downloading rule files

```
wget https://rules.emergingthreats.net/open/suricata-6.0.1/emerging.rules.tar.gz
mkdir et-open
tar -xzf emerging.rules.tar.gz -C et-open/
```

```
cat et-open/rules/*.rules > et-open/combined.rules
```

## Reloading rules via unix-socket

Suricata rule database can be updated without system restart, but this requires `unix-command` to be enabled in `suricata.yaml`. Note that this should be enabled by default, so current section does not require user to set it up.

```
unix-command:
  enabled: auto
  #filename: custom.socket
```

You can use `suricatasc` utility to connect to Unix Socket. **Suricata must be running in online mode**. And use `sudo` as needed.

```
suricatasc
```

If all goes well, then you should see the following help message once connected. More specifically, we are interested in `reload-rules` command.

```
Command list: shutdown, command-list, help, version, uptime, running-mode, capture-mode, conf-get, dump-counters, reload-rules, ruleset-reload-rules, ruleset-reload-nonblocking, ruleset-reload-time, ruleset-stats, ruleset-failed-rules, register-tenant-handler, unregister-tenant-handler, register-tenant, reload-tenant, unregister-tenant, add-hostbit, remove-hostbit, list-hostbit, reopen-log-files, memcap-set, memcap-show, memcap-list, dataset-add, dataset-remove, iface-stat, iface-list, iface-bypassed-stat, ebpf-bypassed-stat, quit
```

Make sure you have read permissions for socket, or just use `sudo` as needed.

```
suricatasc -c "reload-rules"
```

Then add update command with reload to periodic cron task.

## suricata-update

 * https://suricata.readthedocs.io/en/latest/rule-management/suricata-update.html
 * https://suricata-update.readthedocs.io/en/latest/

```
apt-get install python3-pip
python3 -m pip install --upgrade --user suricata-update
```

Official rule update tool is a python script.

```
/home/vagrant/.local/bin/suricata-update --help
/home/vagrant/.local/bin/suricata-update list-sources
```

Enable a new rule source.

```
/home/vagrant/.local/bin/suricata-update enable-source tgreen/hunting
```

Update rules

```
/home/vagrant/.local/bin/suricata-update -D /vagrant
```

Rule directory is usually defined in `suricata.yaml`. But again, you can just use `-S` to point Suricata directly to it.

```
default-rule-path: /var/lib/suricata/rules
rule-files:
 -  suricata.rules
```


### Exercise

* Set up periodic rule update. Rules should be located in `/vagrant/var`. Following rulesets should be activated:
  * `et/open`
  * `oisf/trafficid`
  * `ptresearch/attackdetection`
  * `tgreen/hunting`
  * All suricata rulesets from [sslbl](https://sslbl.abuse.ch/blacklist/)
* Set up a web server for custom rules (use the ones you have already written or create some new ones);
  * Hint - you can use [official nginx docker container](https://hub.docker.com/_/nginx) to quickly create a simple web server.
  * Add your custom rule source to periodic updates;
* Disable following rules:
  * Outbound Curl user-agent;
  * apt and yum package management;
  * Unix and BSD ping;
  * SID `906200077`, `906200082`, `906200087`, `906200088`, `906200048`, `906200047´, ´906200038`, `906200015`;
