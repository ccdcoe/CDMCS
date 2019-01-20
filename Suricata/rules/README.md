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
tar -xzf emerging.rules.tar.gz
ls -lah rules/
```

Please keep an eye out for ruleset version. Newer version of suricata supports keywords that are missing from prior releases. Furthermore, compatibility with snort rules format is no longer a priority for core team, as Suricata has evolved.

```
suricata --list-keywords
suricata -V
```

## Explore the rules directory

Display all enabled rules.
```
grep -h -v '^ *#' *.rules
```

What actions?
```
grep -h -v '^ *#' *.rules | cut -s -d' ' -f1 | sort | uniq -c
```

What protocols?
```
grep -h -v '^ *#' *.rules | cut -s -d' ' -f2 | sort | uniq -c
grep -h -v '^ *#' *.rules | cut -s -d' ' -f2 | sort | uniq -c | sort -n
```

Note that `-h` key will disable filename display for grep while `-v` enables inverse search.

## Tcpdump

 * https://www.sans.org/security-resources/tcpip.pdf
 * https://www.tcpdump.org/tcpdump_man.html
 * https://wiki.wireshark.org/DisplayFilters

Find your interfaces.

```
route -n
ip link show
ip addr show
```

Start the capture process and write all port `80` traffic to pcap file.

```
export IFACE=lo
tcpdump -i $IFACE -w /tmp/capture.pcap port 80 or 443 -n
```

Modern network interface cards try to handle all packet CRC checksums in hardware. Checksums in pcap files are often simply placeholders that do not correspond to actual packet hash values. This can cause troubles for all packet capture tools. Tcprewrite can be used to hack around this issue.

```
tcprewrite -C -i /tmp/infile.pcap -o /tmp/outfile.pcap
```

Generate some traffic

```
curl -v https://www.facebook.com -sL -H 'Connection: close'
```

Load the pcap into suricata

```
suricata -r /vagrant/capture.pcap -vvv
```
## Writing Rule

> Do not write rules, buy from professionals!

 * https://suricata.readthedocs.io/en/latest/rules/intro.html

### basic rule template

```
alert tcp any any -> any any (msg:"testing"; classtype:bad-unknown; sid:990001; rev:1;)
```

### more useful example
```
alert tcp any any -> any 443 (msg:"SURICATA Port 443 but not SSL/TLS"; app-layer-protocol:!tls; threshold: type limit, track by_src, seconds 180, count 1; classtype:bad-unknown;  sid:990002;)
```

A rule consists of the following:
 * action
 * header
 * rule-options

#### Action

 * alert - This is the action we want to perform on the rule
 * pass - This can be compared to “ACCEPT” in iptables, in that if the packet matches this rule it’ll be accepted through.
 * drop - The packet doesn’t get processed any further down the chain and the sender isn’t notified. This is akin to the “DROP” target in iptables, where it will silently remove the packet from the network stack.
 * reject - This acts the same as drop but will also notify the sender that the packet has been removed from the stack.

#### Header

* First keyword: protocol with protocol recognition
* Second part: IP params includin variable

#### Rule options

* content matching
* meta data
* threshold configuration
