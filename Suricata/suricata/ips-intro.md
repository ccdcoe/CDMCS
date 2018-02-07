# Suricata as an IPS

> Maybe it is better to just drop the bad stuff?

see:
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

* This mode is dependent on the zero copy mode of AF_PACKET. You need to set use-mmap to yes on both interfaces.
* MTU on both interfaces have to be equal.
* Set different values of cluster-id on both interfaces to avoid conflict.


----

Next -> [Setting up](ips-setup.md)
