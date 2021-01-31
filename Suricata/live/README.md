# Live capture

Reading static PCAPs on disk is nice for testing or forensics, but goal is to run Suricata online. To see bad stuff as soon as it happens.

## AF-packet

On Linux, Suricata uses a kernel interface called `af-packet` to inspect packets without much overhead. On BSD `netmap` fills the same role.

Note that superuser privileges are needed for writing to interface.

```
sudo suricata --af-packet=$INTERFACE -l logs/
tail -f logs/eve.json
```

## Replay

We can use `tcpreplay` to simulate online environment. Packets can be read from offline PCAP files and written to NIC-s.

```
sudo tcpreplay -i $INTERFACE $PCAP
```

You can also control many aspects of replay. For example, to replay with specific rate, or to loop the replay.

```
sudo tcpreplay --pps=100 --loop=3 -i $INTERFACE $PCAP
```

For exercise or lab setup, you can create a *virtual nic pair* that simulates capture interface. Packets written to one interface can be read from another, just like mirror ports in real life.

```
ip link add capture0 type veth peer name replay0
```

Don't forget to active both endpoints.

```
ip link set capture0 up
ip link set replay0 up
```

Sometimes you might run into packet truncation or size mismatch errors. That's because MTU of box that catured the PCAP was likely higher than default 1512. But you can just configure your capture interfaces for jumbo frames.

```
ip link set dev capture0 mtu 9000
ip link set dev replay0 mtu 9000
```

Packet sizes can vary. Smaller will pass as-is, the MTU config is mainly to ensure that jumbo packets are not truncated.

Then start the replay.

```
sudo tcpreplay -i replay0 $PCAP
```

`tcpdump` can be used to verify raw packets.

```
sudo tcpdump -n -i capture0
```

Then start Suricata listener

```
sudo suricata --af-packet=capture0 -l logs/
tail -f logs/eve.json
```

## Tasks

* Select 3 malware PCAP samples;
* Create a virtual NIC pair for each pcap;
* Start a separate suricata capture process for each PCAP replay;
