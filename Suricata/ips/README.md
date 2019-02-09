# Suricata as an IPS

> Maybe it is better to just drop the bad stuff?

see:
* https://github.com/StamusNetworks/SELKS/wiki/Initial-Setup---Suricata-IPS
* https://home.regit.org/2012/09/new-af_packet-ips-mode-in-suricata/
* https://github.com/OISF/suricata/commit/662dccd8a5180807e3749842508b80e2e2183051

## IPS
Suricata can effectively be used as an IPS. Traditinally, a firewall (e.g., netfilter or ipfw) has been used for achieving this functionality. However, this does not always perform very well.


Since 2012, you could also use Suricata to bridge two network interfaces using the AF_PACKET ips mode. All packets received from one interface are sent to the other interface, unless a signature with drop (or reject) keyword does not fire on the packet.


The copy-mode variable can take the following values:

* ips: the drop keyword is honored and matching packets are dropped.
* tap: no drop occurs, Suricata acts as a bridge


### sample conf:
```
af-packet:
  - interface: eth0
    threads: 1
    defrag: yes
    cluster-type: cluster_flow
    cluster-id: 98
    copy-mode: ips
    copy-iface: eth1
    buffer-size: 64535
    use-mmap: yes
  - interface: eth1
    threads: 1
    cluster-id: 97
    defrag: yes
    cluster-type: cluster_flow
    copy-mode: ips
    copy-iface: eth0
    buffer-size: 64535
    use-mmap: yes
```

### Remember

* This mode is dependent on the zero copy mode of AF_PACKET. You need to set use-mmap to yes on both interfaces;
* MTU on both interfaces have to be equal;
* Set different values of cluster-id on both interfaces to avoid conflict;
* Stream engine must be set into inline mode, that way the engine will keep a session in memory until drop/accept has been decided;

# virtualbox routed setup

## set up static routes on client and server

* client should be routed to server and vice versa, via the bridge machine
* https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/deployment_guide/s1-networkscripts-static-routes
* please disable the first network interface on client machine manually!

```
ip route add default via 192.168.12.254
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
