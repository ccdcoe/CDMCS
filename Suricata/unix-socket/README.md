# Suricata Unix Socket

This section **does not** assume any knowledge about Suricata YAML configuration. Some references to it will be made. But student should be able to repeat all examples without touching the configuration file.

However, the student should be familiar with:
* Using Suricata with CLI flags (`-S`, `-l`, `-r`, `--af-packet=$IFACE`);
* Parsing offline PCAP files / simple traffic replay;
* Rule file, loading that rule file with `-S`;
* Exploring `eve.json` using `jq`;

## Background

* Restarting suricata is a no no. If you have a lot of rules, this will take a long time
* You would not want to miss anything, would you?

## Suricata can listen to a unix socket and accept commands from the user. 

see:
* https://suricata.readthedocs.io/en/latest/unix-socket.html
* https://suricata.readthedocs.io/en/latest/rule-management/rule-reload.html
* https://home.regit.org/2012/09/a-new-unix-command-mode-in-suricata/
* https://github.com/inliniac/suricata/blob/89ba5816dc303d54741bdfd0a3896c7c1ce50d91/src/unix-manager.c#L922

Unix socket can be enabled in YAML cofnig. Note that this should be enabled by default, so current section does not require user to set it up.

```
unix-command:
  enabled: auto
  #filename: custom.socket
```

## Using unix-socket mode

Suricata has many runmodes. Student should already be familiar with `pcap reader` and `af-packet`. However, former will exit as soon as PCAP read is done and latter requires higher privileges with traffic generation to live interface. Both would need to *heat up* the ruleset first. Which is not ideal if you want to process a lot of PCAPs, debug large rulesets, etc.

Solution is to launch suricata in unix socket mode.

```
suricata --unix-socket
suricatasc
```

Note that Suricata would create unix socket regardless of runmode. However, explicit unix socket mode has a few benefits.Many were already mentioned in last paragraph, but this runmode will also enable commands that are unavailable in other runmodes.

Most importantly, you will be able to feed PCAPs along with respective output folders directly to Suricata process running in userspace. Great for network forensics

```
suricatasc -c capture-mode
suricatasc -c "pcap-file $PCAP $LOG_DIR"
```

## Looping over values in bash

```
for pcap in `find /$PCAP_DIR -type f -name '*.pcap'` ; do
  suricatasc -c "pcap-file $pcap $LOG_DIR/$PCAP"
done
```

## Tasks

* Start suricata in unix-socket runmode
* Parse all MTA PCAPs!
