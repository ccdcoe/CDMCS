# virtualbox routed setup

## set up static routes on client and server

* client should be routed to server and vice versa, via the bridge machine
* https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/deployment_guide/s1-networkscripts-static-routes
* please disable the first network interface on client machine manually!

```
ip route add default 192.168.12.254
ip route add 192.168.11.0/24 via 192.168.12.254 dev <DEV>
```
```
ip route show
```

## set up suricata ips on bridge machine

* [suricata will handle packet copy between interfaces, no iptables nor ip_forward setup is needed](/Suricata/suricata/ips-intro.md)

### use tcpdump on bridge machine to debug
```
vagrant ssh bridge
tcpdump -i enpXXX port 80
```
