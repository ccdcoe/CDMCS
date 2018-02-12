# Tcpdump

 * https://www.sans.org/security-resources/tcpip.pdf
 * https://www.tcpdump.org/tcpdump_man.html
 * https://wiki.wireshark.org/DisplayFilters

## find your interface
```
route -n
ip link show
```

## start the capture process
```
echo "I actually read the man before doing this"
export IFACE=lo
tcpdump -i $IFACE -w /tmp/capture.pcap port 80
```

## fixing bad checksumming

```
tcprewrite -C -i /tmp/infile.pcap -o /tmp/outfile.pcap
```


## generate some traffic

```
curl -v https://www.facebook.com -sL -H 'Connection: close'
```

## load the pcap into suricata

```
suricata -r /vagrant/capture.pcap -vvv
```

----
Next -> [write a rule](rules.writing.md)
