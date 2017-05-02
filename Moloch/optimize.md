# optimization

* https://github.com/pevma/SEPTun
* https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Performance_Tuning_Guide/s-cpu-irq.html
* https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Packet_Capture

```
ethtool -l <interface>
```

```
cat /proc/interrupts
```

```
GRUB_CMDLINE_LINUX_DEFAULT="processor.max_cstate=3 intel_idle.max_cstate=3 apparmor=0 mce=ignore_ce isolcpus=17-31"
```

```
apt-get install hwloc
lstopo --logical --output-format txt
```

```
#!/bin/bash

DIR=/opt/moloch/logs/
cd $DIR
ulimit -n 240000

#systemctl restart molochwise.systemd.service
#pgrep node | while read line; do taskset -pc 1-15 $line ; done

sleep 2

nohup /opt/moloch/bin/moloch-capture -c /opt/moloch/etc/config.ini &

sleep 3

taskset -pc 16  `pstree -Aap | pcregrep -o2 '(moloch-pcap\d+)},(\d+)' | sort -n`
taskset -pc 16  `pstree -Aap | pcregrep -o2 '(moloch-simple)},(\d+)' | sort -n`
taskset -pc 16  `pgrep moloch-capture`

num=18

for pid in `pstree -Aap | pcregrep -o2 '(moloch-pkt\d+)},(\d+)' | sort -n`; do
  taskset -pc $num $pid && num=$((num+1))
done
```
