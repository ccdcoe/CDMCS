# suricata-update

This section **does not** assume any knowledge about Suricata YAML configuration. Some references to it will be made. But student should be able to repeat all examples without touching the configuration file.

However, the student should be familiar with:
* Using Suricata with CLI flags (`-S`, `-l`, `-r`, `--af-packet=$IFACE`);
* Parsing offline PCAP files / simple traffic replay;
* Rule file, loading that rule file with `-S`;
* Exploring `eve.json` using `jq`;
* Suricata rulesets, downloading them manually, rule file layout, loading ruleset with `-S`;

 * https://suricata.readthedocs.io/en/latest/rule-management/suricata-update.html
 * https://suricata-update.readthedocs.io/en/latest/

```
apt-get install python3-pip
python3 -m pip install --upgrade --user suricata-update
```

Official rule update tool is a python script.

```
$HOME/.local/bin/suricata-update --help
$HOME/.local/bin/suricata-update list-sources
```

Enable a new rule source.

```
$HOME/.local/bin/suricata-update enable-source tgreen/hunting
```

Update rules

```
$HOME/.local/bin/suricata-update -D $WORKING_DIR
```

Rule directory is usually defined in `suricata.yaml`. But again, you can just use `-S` to point Suricata directly to it.

```
default-rule-path: /var/lib/suricata/rules
rule-files:
 -  suricata.rules
```

# Exercise

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
