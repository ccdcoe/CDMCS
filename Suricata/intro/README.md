# Suricata

see:
 * http://suricata-ids.org/
 * http://planet.suricata-ids.org/
 * http://www.openinfosecfoundation.org/
 * https://github.com/inliniac/suricata
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

### Simply running from cli

```
cat /etc/suricata/rules/*.rules >> /tmp/all.rules
mkdir /tmp/log
```

```
suricata --af-packet=$ETH -l /tmp -s /tmp/all.rules  -vvv
```
