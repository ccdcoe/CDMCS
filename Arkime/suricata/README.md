# Integrating Suricata with Arkime

Arkime has a plugin for Suricata which enables enriching sessions with Suricata alerts. This allows for filtering sessions which have triggered a Suricata alert.

Requirements for the plugin to work:

 * Suricata and Arkime Capture must see the same traffic.
 * Arkime must be able to access the eve.json log from Suricata.
 * Arkime will try match sessions based on the 5-tuple from the eve.json file.
 * Only events with the event type of `alert` are considered. 

Expected outcome

 * This plugin adds new fields to Arkime (similarly to like wise and tagger).
 * Sessions that have been enriched will have several new fields, all starting with the `suricata` prefix. 
 * There will be a separate `Suricata` sub-section in the Arkime sessions view. 
 * A query to find all sessions that have Suricata data is `suricata.signature == EXISTS!`.


## Configure Arkime

Append `suricata.so` to your `config.ini` plugins line

```
plugins=wise.so,suricata.so
```

`suricataAlertFile` should be the full path to your eve.json file. `suricataExpireMinutes` option specifies how long Arkime will keep trying to match past suricata events. Note: When processing old PCAPs you need to compensate for the time from `now() - pcap-record-date`.

```
suricataAlertFile=/var/log/suricata/eve.json
suricataExpireMinutes=60
```

## Install and (minimally) configure Suricata

Naturally you will also need Suricata. If it's not already installed, you need to install it.

For Ubuntu there's a [PPA for Suricata](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Ubuntu_Installation_-_Personal_Package_Archives_%28PPA%29), so that's the most convenient way of installing the latest stable version of Suricata.

```
apt-get install software-properties-common
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata 
```

That's it! Suricata is installed. However let's check the Suricata log file `/var/log/suricata/suricata.log`.

```
13/6/2023 -- 19:36:20 - <Error> - [ERRCODE: SC_ERR_AFP_CREATE(190)] - Unable to find iface eth0: No such device
13/6/2023 -- 19:36:20 - <Error> - [ERRCODE: SC_ERR_AFP_CREATE(190)] - Couldn't init AF_PACKET socket, fatal error
13/6/2023 -- 19:36:20 - <Error> - [ERRCODE: SC_ERR_FATAL(171)] - thread W#01-eth0 failed
```

We need to modify `/etc/suricata/suricata.yaml` file to point Suricata to the correct network interface

```
# Linux high speed capture support
af-packet:
  - interface: enp11s0
```

Restart the Suricata systemd service and check the logs again.

```
systemctl restart suricata.service
less /var/log/suricata/suricata.log 
```

The errors for the interface should be gone now. However check if and how many Suricata rules/signratures were loaded?

```
13/6/2023 -- 19:36:20 - <Warning> - [ERRCODE: SC_ERR_NO_RULES(42)] - No rule files match the pattern /var/lib/suricata/rules/suricata.rules
13/6/2023 -- 19:36:20 - <Config> - No rules loaded from suricata.rules.
13/6/2023 -- 19:36:20 - <Warning> - [ERRCODE: SC_ERR_NO_RULES_LOADED(43)] - 1 rule files specified, but no rules were loaded!
```

Suricata has a Rule management tool called `suricata-update`. 

```
# see various options
suricata-update --help
# Fetch ET Open ruleset for Suricata
suricata-update --etopen
```

You should see something like

```
13/6/2023 -- 19:52:30 - <Info> -- Writing rules to /var/lib/suricata/rules/suricata.rules: total: 42944; enabled: 34152; added: 42944; removed 0; modified: 0
```

Once again, restart the Suricata service to make sure the new rules are loaded.

```
systemctl restart suricata.service
less /var/log/suricata/suricata.log 
```

```
13/6/2023 -- 20:28:54 - <Config> - Loading rule file: /var/lib/suricata/rules/suricata.rules
13/6/2023 -- 20:29:02 - <Info> - 1 rule files processed. 34152 rules successfully loaded, 0 rules failed
13/6/2023 -- 20:29:02 - <Info> - Threshold config parsed: 0 rule(s) found
13/6/2023 -- 20:29:02 - <Info> - 34155 signatures processed. 1277 are IP-only rules, 5214 are inspecting packet payload, 27457 inspect application layer, 108 are decoder event only
```

## Checking the results

Now that Suricata is installed and running, we can restart our Arkime Capture and Viewer, so that our earlier changes will take effect. Arkime Capture will load the Suricata module and start parsing the eve.json file.

```
systemctl restart arkimecapture.service
systemctl restart arkimeviewer.service
```

We need some traffic that would fire off a Suricata alert.

```
curl -s http://www.testmyids.com
```

Wait for the session to get indexed and see the results from Arkime Viewer. You can use the filter `suricata.signature == EXISTS!` for finding sessions with Suricata matches.

