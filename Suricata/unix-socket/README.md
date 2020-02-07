# Suricata Unix Socket

> Restarting suricata is a no no. If you have a lot of rules, this will take a long time
> You would not want to miss anything, would you?

### Suricata can listen to a unix socket and accept commands from the user. 

see:
* https://suricata.readthedocs.io/en/latest/unix-socket.html
* https://suricata.readthedocs.io/en/latest/rule-management/rule-reload.html
* https://home.regit.org/2012/09/a-new-unix-command-mode-in-suricata/
* https://github.com/inliniac/suricata/blob/89ba5816dc303d54741bdfd0a3896c7c1ce50d91/src/unix-manager.c#L922

samples: 
* https://github.com/hillar/vagrant_suricata_influxdb_grafana/blob/master/suri-influxdb.py
* https://gist.github.com/hillar/309e93d5b555095d07b9

# load pcaps
see

 * https://suricata.readthedocs.io/en/latest/command-line-options.html?highlight=pcap#cmdoption-r
 * https://suricata.readthedocs.io/en/latest/unix-socket.html?highlight=unix%20socket#pcap-processing-mode

get some pcaps:

* https://suricata.readthedocs.io/en/latest/public-data-sets.html
* http://www.malware-traffic-analysis.net/training-exercises.html

## Configuration

```
grep 'unix-command' -B6 -A2 /etc/suricata/suricata.yaml
suricata --help | grep unix
```


## Using existing tool to interact with socket

Run Suricata in unix-socket mode

```
/usr/bin/suricata --unix-socket
```

```
suricatasc --help
suricatasc -c capture-mode
suricatasc -c "pcap-file /tmp/mycapture.pcap /tmp/capturelogs"
suricatasc -c "pcap-file /tmp/pcapdir /tmp/capturelogs"
```

## Checksum errors

Checksums in pcap files are often simply placeholders that do not correspond to actual packet hash values. This can cause troubles for all packet capture tools. tcprewrite (from the tcpreplay package) can be used to hack around this issue.

```
apt-get install tcpreplay
tcprewrite -C -i /tmp/infile.pcap -o /tmp/outfile.pcap
```

Alternatively you can disable checksum checks for PCAPs loaded via unix socket by changing the following in the suricata.yaml

```
pcap-file:
  checksum-checks: no
```

## Looping over values in bash

```
for pcap in `find /pcapdir -type f -name '*.pcap'` ; do
	echo "I am doing stuff with $pcap"
done
```


## Tasks
 * Start suricata in unix-socket runmode
 * Run suricatasc and find commands for loading in PCAPs
 * Load multiple PCAPs using suricatasc
 * Check results in suricata output/logs

