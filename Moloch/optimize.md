# optimization

* https://github.com/pevma/SEPTun
* https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Performance_Tuning_Guide/s-cpu-irq.html
* https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_MRG/1.3/html/Realtime_Tuning_Guide/sect-Realtime_Tuning_Guide-General_System_Tuning-Interrupt_and_Process_Binding.html
* https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Packet_Capture
* https://www.kernel.org/doc/Documentation/IRQ-affinity.txt
* https://github.com/pevma/SEPTun
* https://github.com/pevma/SEPTun-Mark-II

Show RSS settings

```
ethtool -l <interface>
```

Show system interrupts

```
cat /proc/interrupts
```

```
ifconfig
cat /proc/interrupts | grep enp0s25
cat /proc/irq/28/smp_affinity
```

```

```

Isolate specific CPU cores from kernel. Linux will no longer schedule anything on them.

```
GRUB_CMDLINE_LINUX_DEFAULT="processor.max_cstate=3 intel_idle.max_cstate=3 apparmor=0 mce=ignore_ce isolcpus=17-31"
```

But which cores do I want to isolate (i.e., what is NUMA)?

```
apt-get install hwloc
lstopo --logical --output-format txt
```

We want to assign specific threads to specific cores, and we want them to stay there. Just make sure to offload any thread-heavy support services to other machines (e.g. elasticsearch, logging, etc.).

```
systemctl stop irqbalaner.service
systemctl disable irqbalaner.service
```

Then start your processes and assign them to specific cores.

```
taskset -pc $core_num $pid
```

And yes, per-thread affinity manually is really annoying.

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
