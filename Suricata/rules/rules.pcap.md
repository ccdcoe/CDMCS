# Tcpdump

 * https://www.sans.org/security-resources/tcpip.pdf
 * https://www.tcpdump.org/tcpdump_man.html


## find your interface
```
ip link show
```

## start the capture process
```
echo "I actually read the man before doing this"
export IFACE=lo
tcpdump -i $IFACE -w /tmp/capture.pcap port 80
```

## generate some traffic

```
curl -s http://sysadminnid.tumblr.com/ > /dev/null 2>&1
```
