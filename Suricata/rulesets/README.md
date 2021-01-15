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
python3 -m pip install --user yq
```

```
curl -ss https://raw.githubusercontent.com/OISF/suricata-intel-index/master/index.yaml | ~/.local/bin/yq '.sources | .[] | .url'
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

## Show and tell

Demo session for exploring rulesets with a Jupyter notebook. For showing how rulesets are structured, how many rules there are, how rules are usually written by professionals. Not meant to be a hands-on session for students.

```
python3 -m pip install --user --upgrade jupyter jupyterlab pandas numpy idstools
export PATH="$HOME/.local/bin:$PATH"
```
