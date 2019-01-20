# Suricata rules

> Suricata alerting is rule-based. Commonly, rulesets are externally developed.

> There are multiple rule sources, some free some commertial

> You need to manage and update your rules every day!

> https://suricata.readthedocs.io/en/latest/rules/

Possible sources:
* https://rules.emergingthreats.net/open/
* https://github.com/ptresearch/AttackDetection#suricata-pt-open-ruleset
* https://github.com/OISF/suricata-trafficid
* https://raw.githubusercontent.com/travisbgreen/hunting-rules/master/hunting.rules

rule managers:
* [suricata-update](https://github.com/OISF/suricata-update)
* [scirius](/Suricata/scirius/README.md)

rule writing tools:
* [dalton + flowsynth](https://github.com/secureworks/dalton)

## Getting the emerging threats ruleset 

ET open is the default ruleset packaged with suricata. However, it can be downloaded separately.

```
wget -4 http://rules.emergingthreats.net/open/suricata-4.1/emerging.rules.tar.gz
tar -xzf emeging.rules.tar.gz
```

Please keep an eye out for ruleset version. Newer version of suricata supports keywords that are missing from prior releases. Furthermore, compatibility with snort rules format is no longer a priority for core team, as Suricata has evolved.

```
suricata --list-keywords
suricata -V
```

## A quick look into what kind of rules we have

* How many rules do we have?

Remove all comments
```
grep -v '^ *#' *.rules
```

What actions?
```
grep -v '^ *#' *.rules | cut -s -d' ' -f1 | sort | uniq -c
```

What protocols?
```
grep -v '^ *#' *.rules | cut -s -d' ' -f2 | sort | uniq -c
grep -v '^ *#' *.rules | cut -s -d' ' -f2 | sort | uniq -c | sort -n
```

----
Next -> [capture some traffic](rules.pcap.md)
