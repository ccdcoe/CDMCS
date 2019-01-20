# Rules

> Suricata alerting is rule-based. Commonly, rulesets are externally developed.
> There are multiple rule sources, some free some commertial
> You need to manage and update your rules every day!

## Getting the emerging threats ruleset 

ET open is the default ruleset packaged with suricata. However, it can be downloaded separately.

```
wget -4 http://rules.emergingthreats.net/open/suricata-4.1/emerging.rules.tar.gz
tar -xzf emeging.rules.tar.gz
```

Please keep an eye out for ruleset version. Newer version of suricata supports keywords that are missing from prior releases. Furthermore, compatibility with snort rules format is no longer a priority for core team, as Suricata has evolved.

```
suricata --list-keywords
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
