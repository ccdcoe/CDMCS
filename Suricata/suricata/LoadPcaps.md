# load pcaps

see

 * http://suricata.readthedocs.io/en/latest/command-line-options.html?highlight=pcap#cmdoption-r
 * http://suricata.readthedocs.io/en/latest/unix-socket.html?highlight=unix%20socket#pcap-processing-mode

get some pcaps:

* http://suricata.readthedocs.io/en/latest/public-data-sets.html
* http://www.malware-traffic-analysis.net/training-exercises.html

## Configuration

```
grep 'unix-command' -B5 -A2 /etc/suricata/suricata.yaml
```

```
suricata --help | grep unix
```

## For loop is easy?

```
for pcap in `find /pcapdir -type f -name '*.pcap'` ; do
	echo "I am doing stuff with $pcap"
done
```

## Using existing tool to interact with socket

```
suricatasc --help
```
