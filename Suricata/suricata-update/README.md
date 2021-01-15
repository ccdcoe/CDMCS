# suricata-update

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
$HOME/.local/bin/suricata-update -D /vagrant
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
