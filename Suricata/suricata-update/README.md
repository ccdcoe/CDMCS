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
 
## Background
 
* Downloading rules for first time is easy
* But ongoing rule management (on CLI) used to be a pain
* People had to use oldschool Snort tools like Oinkmaster or pulledpork
* Or write their own update scripts
* Trickier than it sounds, as rule manager needs to:
  * Download rules (from multiple sources)
  * Disable and modify rules according to your use cases
  * Ensure that next rule update does not overwrite yesterdays modifications!
* No modern lightweight tools existed

## Enter suricata-update

Now there's a modern tool directly from Suricata dev team. It's called `suricata-update`. It's provided with suricata
sources and it is also very easy to install with `pip`

```
apt-get install python3-pip
python3 -m pip install --upgrade --user suricata-update
```

First thing, check the `--help` flag. It has quite a lot functionality.

```
$HOME/.local/bin/suricata-update --help
```

### Adding a source

Predefined sources can be listed with `list-sources` subcommand.

```
$HOME/.local/bin/suricata-update list-sources
```

By default, only `et/open` is enabled. Other rule sources can be enabled with `enable-source` subcommand, with source name (that you found via `list-sources`) following that command.

```
$HOME/.local/bin/suricata-update enable-source tgreen/hunting
```

Note that default working directory for suricata-update is `/var/lib/suricata`. However, you might be running it as regular user. And you should be. **Downloading or modifying ruleset does not require admin privileges.** Permissions only come into play when reloading Suricata itself.

Working directory can easily be overridden with `-D` flag. If you see **permission denied** or **working dir missing**, keep in mind that you can just use something else! And whatever you choose is up to you!

```
$HOME/.local/bin/suricata-update enable-source tgreen/hunting -D $WORKING_DIR
```

Calling `suricata-update` with no subcommand would then download all rules and merge them into `suricata.rules` in working directory of your choice.

```
$HOME/.local/bin/suricata-update -D $WORKING_DIR
cat $WORKING_DIR/rules/suricata.rules | wc -l
```

Rule directory is usually defined in `suricata.yaml`. But again, you can just use `-S` to point Suricata directly to it.

```
default-rule-path: $WORKING_DIR/rules
rule-files:
 -  suricata.rules
```

```
suricata -S $WORKING_DIR/rules/suricata.rules $OPTS
```

### Disabling a source

Disabling a source simply means calling `remove-source`, re-running update and reloading Suricata.

```
suricata-update remove-source tgreen/hunting -D $WORKING_DIR
```

```
$HOME/.local/bin/suricata-update -D $WORKING_DIR
```

### Configuration files

`suricata-update` can parse multiple config files to apply ruleset transformations. Use `--dump-sample-configs` to have suricata-update dump their skeletons to local folder. Good idea is to create a separate clean folder for them.

```
mkdir configs
cd configs
suricata-update --dump-sample-configs
```

It will give you:
* `update.yaml` for suricata-update itself;
* `disable.conf` for disabling rules, SIDs, rule categories, rule files, etc;
* `enable.conf` for the reverse;
* `drop.conf` for IPS `drop` conversion;
* `modify.conf` for rule customizations;
* `threshold.in` for threshold setup;

For example, `malware.rules` can be disabled with following content in `disable.conf`. Just a sample, that's actually one rule category you don't want to disable!

```
group: emerging-malware.rules
```

Then run `suricata-update` while pointing it toward `disable.conf`.

```
$HOME/.local/bin/suricata-update -D $WORKING_DIR  --disable-conf disable.conf
```

# Exercise

* Set up periodic rule update. Rules should be located in `/vagrant/var`. Following rulesets should be activated:
  * `et/open`
  * `oisf/trafficid`
  * `ptresearch/attackdetection`
  * `tgreen/hunting`
* Disable following rules:
  * Outbound Curl user-agent;
  * apt and yum package management;
  * Unix and BSD ping;
