# Suricata rules

> Suricata alerting is rule-based. Commonly, rulesets are externally developed.
> There are multiple rule sources, some free some commertial
> You need to manage and update your rules every day!

This is a simple getting started page for writing your first rule. Please refer to [official documentation](https://suricata.readthedocs.io/en/latest/rules/) for more information.

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
wget -4 http://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz
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

## Generating packets for testing

 * https://www.sans.org/security-resources/tcpip.pdf
 * https://www.tcpdump.org/tcpdump_man.html
 * https://wiki.wireshark.org/DisplayFilters

Find your interfaces that will be talking to the destination.

```
route -n
ip link show
ip addr show
ip route show
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

Or, you can capture traffic on the wire.

```
suricata --af-packet=$ETH -l logs/ -vvv
```

However, note that can be considerably more difficult (or annoying) to reproduce with live traffic.

## Writing your first rule

> Do not write rules, buy from professionals!

 * https://suricata.readthedocs.io/en/latest/rules/intro.html

### basic rule template

Create a new file for custom rules.

```
vim rules/custom.rules
```

Then enter this skeleton.

```
alert tcp any any -> any any (msg:"testing"; classtype:bad-unknown; sid:990001; rev:1;)
```

Finally, run suricata from command line against the pcap file from prior step while exclusively loading your rule file. Note that we also redefine our default logging directory, so we are able to see the output.

```
suricata -S /vagrant/custom.rules -r /vagrant/my.pcap -l logs/ -vvv
```

Checksum errors can also be ignored with `-k` flag. That way we do not have to rewrite our pcap file nor disable checksum offloading.

```
suricata -S /vagrant/custom.rules -r /vagrant/my.pcap -l logs/ -vvv -k none
```

But the proper way to solve this probleb is by [disabling NIC offloading fucntions](/Suricata/intro#disable-nic-offloading) and then regenerating the pcap.

Fast log is human-readable plaintext format from Snort days. 

```
cat logs/fast.log
```

While good for debugging and developing rules, fast log pretty much deprecated in favor of eve JSON format logs.

```
cat logs/eve.json | jq .
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

## Exercise - write rules that trigger on following conditions

### Basic tasks for introduction

* Facebook certificate
* DNS domain with .su suffix
* DNS zone transfer
* Detection of popular default user-agesnts:
  * Python;
  * Nikto;
  * Dirbuster;
  * Nmap;
  * Curl

### More complex tasks once we have covered some config aspects

* TLS connection from HOME_NET to toto.com domain (we need to exclude toto.communism.fr)
* Alert on JPEG image taken with a NIKON D700 (example: http://home.regit.org/wp-content/uploads/2017/07/20170705_0237.jpg)
* Set up a simple web server with `python3 -m http.server` and create 5 files with some content in it;
  * 2 files are *confidential* - you should get an alert whenever someone accesses them via HTTP GET;
  * You should not get an alert for other files;
  * Modify this rule, so that alerts are only generated when files are downloaded from **CONFIDENTIAL_SERVER**;
