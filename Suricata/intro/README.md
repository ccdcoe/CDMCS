# Suricata

see:
 * http://suricata-ids.org/
 * http://planet.suricata-ids.org/
 * http://www.openinfosecfoundation.org/
 * https://github.com/OISF/suricata
 * http://suricata.readthedocs.io/en/latest/

![logo](https://idsips.files.wordpress.com/2012/09/suricata.png)


> Suricata is a high performance Network IDS, IPS and Network Security Monitoring engine.

> Suricata implements a complete signature language to match on known threats, policy violations and malicious behaviour. Suricata will also detect many anomalies in the traffic it inspects.

> Suricata will automatically detect protocols such as HTTP on any port and apply the proper detection and logging logic. Suricata can log HTTP requests, log and store TLS certificates, extract files from flows and store them to disk.


## Basic usage

This is just a bare minimum needed to run suricata from CLI on debian or ubuntu machine. Not much useful stuff we can do yet.

### Install on Debian and Ubuntu

> **[OISF](http://oisf.net)** maintains a **PPA suricata-stable** that always contains the latest stable release.

see:
* https://suricata.readthedocs.io/en/latest/install.html

```

add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata
```

```
suricata -V
suricata --help
```

### Disable nic offloading

```
ethtool -K $ETH tx off sg off gro off gso off lro off tso off
```

This task is done automatically when starting recent Suricata. However, everyone that does packet capture needs to know about this!

### Runmodes (major ones)

* Offline PCAP read;
  * useful for testing and forensics;
  * `-r $PCAP_FILE`;
  * pointing to directory will continue sessions (assumes sequential PCAPs);
* Online AF-PACKET mode 
  * low overhead;
  * interfaces with Linux kernel;
  * de-facto standard for live capture (Linux);
    * netmap does the same on BSD;
  * no need to pull packet to userspace;
  * zero-copy goodness;
  * `--af-packet=$IFACE`;
* Unix-socket mode;
  * [separate topic](/Suricata/unix-socket);
  * think of this as online version of PCAP read mode;
  * offline forensics;
  * timesaver and quality of life improvement (no engine restart);
  * tradeoff, config testing needs engine restarts anyway and not a big deal with small rule files;

### Simply running from cli

* `-l` log directory;
* `-r` for reading PCAP file, or `--af-packet=$IFACE` with `$IFACE` reflecting a network interface on your system;
* `-S` to exclusively load a rule file (don't worry, that rule file can be empty), or `--disable-detection` to disable rule engine;
* `-v`, `-vv` or `-vvv` to increase Suricata logging verbosity;

Read offline PCAP file.

```
suricata -r $PCAP_FILE -l $LOG_DIR -S $EXCLUSIVE_RULE_FILE
```

Read online AF-PACKET interface. **Needs elevated privileges.**

```
suricata --af-packet=$IFACE -l $LOG_DIR -S $EXCLUSIVE_RULE_FILE
```

Use suricata without signature engine to only generate protocol logs.

```
suricata --af-packet=$IFACE -l $LOG_DIR --disable-detection
```

### Docker install

Note that Suricata works just fine when set up using docker. [There is an official image for that](https://github.com/jasonish/docker-suricata#usage). Though building one for yourself is not too difficult. **Official image is very minimal, many features are missing.**

```
docker run --rm -ti jasonish/suricata --help
```

Note that docker images usually have a default command or entrypoint. That means, you don't need to call `suricata` binary, as it is already packaged with the container. You simply need to call for arguments. Also note that this does not apply to other binaries inside the image. If you want to call `suricata-update` instead, then you need to explicitly do so.

```
docker run --rm -ti jasonish/suricata suricata-update --help
```

Do note that container usage and arguments depend on how the image was built. There is not single way to do these things. You simply need to [read the Dockerfile](https://github.com/jasonish/docker-suricata/blob/master/Dockerfile) and [entrypoint script](https://github.com/jasonish/docker-suricata/blob/master/docker-entrypoint.sh).

## Rules

* Suricata alerting is rule-based; 
* Commonly, rulesets are externally developed;
* There are multiple rule sources: some free, some commercial;
* You need to manage and update your rules every day!;

This is a simple getting started page for writing your first rule. Please refer to [official documentation](https://suricata.readthedocs.io/en/latest/rules/) for more information.

### Possible sources:

Free sources:

* https://rules.emergingthreats.net/open/
* https://github.com/ptresearch/AttackDetection#suricata-pt-open-ruleset
* https://github.com/OISF/suricata-trafficid
* https://raw.githubusercontent.com/travisbgreen/hunting-rules/master/hunting.rules

Paid sources:

* ETPro
* SecureWorks

## PCAP

### Generating packets for testing

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
suricata -r /vagrant/capture.pcap -l logs/ -S custom.rules -vvv
```

Or, you can capture traffic on the wire.

```
suricata --af-packet=$ETH -l logs/ -S custom.rules -vvv
```

Do note that replicating test cases can become much more difficult with live traffic.

## Writing your first rule

 * Do not write rules, buy from professionals!
 * https://suricata.readthedocs.io/en/latest/rules/intro.html

### basic rule template

Create a new file for custom rules.

```
vim rules/custom.rules
```

Then enter this skeleton. It will alert on every TCP session, regardless of direction.

```
alert tcp any any -> any any (msg:"testing"; sid:990001; rev:1;)
```

And run Suricata from command line against the pcap file from prior step while exclusively loading your rule file. Logging goes to custom directory.

```
suricata -S rules/custom.rules -r /vagrant/my.pcap -l logs/ -vvv
```

Checksum errors can also be ignored with `-k` flag. That way we do not have to rewrite our PCAP file nor disable checksum offloading.

```
suricata -S rules/custom.rules -r /vagrant/my.pcap -l logs/ -vvv -k none
```

But the proper way to solve this problem is by [disabling NIC offloading fucntions](/Suricata/intro#disable-nic-offloading) and then regenerating the PCAP.

Fast log is human-readable plaintext format inspired from Snort days. 

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
* Second part: IP params including variable

#### Rule options

* content matching
* meta data
* threshold configuration

#### Buffers

* Suricata matches on entire packet payload by default;
* Suricata also parses protocol fields;
  * http user-agent;
  * http URI;
  * tls SNI;
  * SSL certificate;
  * DNS query;
  * ...
* Can drill down using *content modifiers* or *sticky buffers*;
* content modifier uses underscores and comes **after** *content*;
  * tls_sni;
  * http_user_agent;
* sticky buffer uses dots and comes **before *content*;
  * tls.sni;
  * http.user-agent;
* *content modifiers* are going the way of the Dodo;

## Tasks

Helpers:
* Generate HTTP / TLS traffic:
  * `curl https://www.facebook.com`;
  * `curl testmyids.com`;
* Generate DNS queries;
  * `dig A www.google.com @1.1.1.1`;
  * `dig AAAA www.google.com @1.1.1.1`;
  * `dig NS google.com @1.1.1.1`;
  * `dig MX google.com @1.1.1.1`;
* Generate DNS zone transfer;
  * `dig AXFR berylia.org @1.1.1.1`;

Write rules for:
* Facebook dns request
* Facebook certificate
* DNS domain with .su suffix
* DNS zone transfer
  * hint - no keyword will help here, you need to hunt raw bytes with wireshark
  * hint - mind the protocol
* Detection of popular default user-agents (use `curl -A`):
  * Python;
  * Nikto;
  * Dirbuster;
  * Nmap;
  * Curl
