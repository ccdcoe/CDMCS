# Optimizing the capture

All credit goes to:
  * https://github.com/pevma/SEPTun
  * https://github.com/pevma/SEPTun-Mark-II

Note that each network card has different capabilities. A lot of notes here simply cannot be done on a vagrant virtual machine.

## **MUST-HAVE** - disable NIC offloading

Modern NIC-s can offload a lot of stuff to hadrware. For example, packet checksumming. This is really good for hosting serices and routing. We don't care! We want the full packet! Otherwise, how can we properly reconstruct the session!

```
for iface in enp130s0f1 enp130s0f0 ; do
  for i in rx tx tso ufo gso gro lro tx nocache copy sg txvlan rxvlan; do
    ethtool -K $eth $i off 2>&1 > /dev/null;
  done
done
```

Note, moloch has likely already complained about this before. Sometimes it even exists during live mode when partial traffic is detected.

## The RSS thing

In short, if you are using multiple networking queues on your NIC, then your capture will have a bad time. And you may not even know about it.

See:

  * https://suricata.readthedocs.io/en/latest/performance/packet-capture.html?highlight=rss#rss
  * https://github.com/pevma/SEPTun/blob/master/SEPTun.rst#common-misconceptions---part-1
  * https://github.com/pevma/SEPTun/blob/master/SEPTun.rst#correct-nic-driver-with-correct-parameters
  * https://github.com/pevma/SEPTun-Mark-II/blob/master/SEPTun-Mark-II.rst#setup-symmetric-hashing-on-the-nic

tl;dr - all traffic is RX for capture box, but NIC decides which queue should handle the traffic based on 5-tuple. That decicion is asymmetric, so RX and TX may end up in different queues. That is bad, mkay.

There are a few options:
  * use a single NIC queue if amount of traffic and packet interrutps is not a problem;
  * use a NIC that supports symmetric flow hasing AND patch your NIC driver and ethtool;
  * use the [low entropy hash trick](http://www.ndsl.kaist.edu/~kyoungsoo/papers/TR-symRSS.pdf);
  * buy an expensive capture card that does packet reordering in hardware;
  * hipster tech that moloch does not currently support (looking at you ebpf and XDP);

### Using a single NIC queue

Check how many queues are actually used:

```
ethtool -l $iface
```

Then change that number to 1.

```
ethtool -L $iface combined 1
```

You should pin this thread to a specific core and make sure that nothing else is scheduled there (see cpu affinity in later secionts). You can see the interrupt handler id by grepping for interface name from this `/proc/interrupts`. Then under `/proc/irq`, look for that id and find the affinity from `smp_affinity_list` file (requires 3.someting kernel, otherwise use `smp_affinity` which is same thing in hex).

```
cat /proc/interrupts | grep $iface
cat /proc/irq/$id/smp_affinity_list
```

You can pin irq hander to a specific thread. For example, if you want thread `1` to handle all interrupts for a specific NIC ring, you can do this:

```
echo 1 > /proc/irq/$id/smp_affinity_list
```

Note that all this work will be totally pointless unless you don't disable the irqbalaner daemon. It will override your configs.

```
systemctl stop irqbalaner.service
systemctl disable irqbalaner.service
```

This method has a nasty limit - you only have one CPU core for handling all NIC interrupts. If that core is saturated, then new packets will no longer be picked up from ringbuffer by the kernel. In other words, you are burining one CPU thread and are limited to 1-2 million PPS, depending on CPU frequency (1 million on an average 2.4GHz XEON seems to be a valid roof). It may seem a lot, but average PPS for LS was ~200k with packet deduplication (x3 without), with 500k-700k peaks. That is already a 50-70% core saturation on peak traffic.

### Low entropy hashing

There is another way to handle this problem. Some smart people figured out that you can archieve symmteric hashing that also provides nearly perfect load balancing by replacing your NIC hash key. First, configure whatever number of queues you'd like. 

```
ethtool -L $iface combined 18
ethtool -K $iface rxhash on
ethtool -K $iface ntuple on
```

Then, we can override the default hash key with a low-entropy one that is essentially just a repeating bit pattern.

```
ethtool -X $iface hkey 6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A equal 18
```

And use a script to pin those irq handlers to specific threads. For example, if NUMA node our NIC is connected to has 20 cores, 0-9 and 20-29. This is also the reason for selecting 18 queues - few should be reserved for management and logging threads, otherwise number of queues should be equal to number of packet workers.

```
set_irq_affinity 1-9,21-29 $iface
```

This approach is less proven than others. Septun mark II article used ixgbe driver with 40bit hash key, but Intel x710 card uses a 52bit key instead. Since it's the repeating pattern that causes symmetric effect, then extending that pattern to fill 52 bits is quite simple, and the results seemed to be quite okay. But this observation is far from scientific. Also, a low-end x520-da2 with ixgbe driver did not allow me to change the hash key at all, so you are still at the mercy of your capture card features. This approach does let you to totally cheap out.

## CPU affinity and NUMA

Modern server usually has multiple CPU-s. Those cpus might not be apparent by simply looking at `top`, but in reality whenever a thread has to access memory that belongs to another CPU, it has to go through motherboard lanes. That introduces latency (compared to local access times). Furthermore, each PCI-e device is connected to a specific NUMA node. **We want our capture process to be bound to same NUMA, CPU and memory, as our physical capture card**. That way, we can rely on higher performance thanks to more frequent L3 cache hits (direct cache access should be enabled in bios). But even without those cache hits, reduction in memory latency is a really good thing. (Near) real-time is a facinating world of wonder and awe...

Start by exploring the topology.

```
apt-get install hwloc
lstopo --logical --output-format txt
```

Ask from a tool meant to understand NUMA. Numbers from `lstopo` may not correspond to what you see in `htop`. Sometames odd numbered threads are numa 0 while even numbered are numa 1. Other times, 0-19 is 0 and 20-39 is 1. Other times, 0-9 is 0, 10-19 is 1, 20-29 is 0, 30-39 is 1. Depends on your hardware, kernel, etc.

```
numactl --hardware
```

`lscpu` command can also tell you which CPU threads belong to which NUMA node. Then start your processes and assign them to specific cores.

```
taskset -pc $core_num $pid
```

Or even better, start capture process with `numactl` instead, as it keeps all threads on correct node and even confines the process to local memory. The latter is a big deal - memory latency is the whole reason we do this!

```
numactl --cpunodebind=1 --membind=1 /data/moloch/bin/moloch-capture -c /data/moloch/etc/config.ini
```

We can also bind the process to the same NUMA node where our capture interface is located.

```
/usr/bin/numactl --cpunodebind=netdev:$iface --membind=netdev:$iface /data/moloch/bin/moloch-capture -c /data/moloch/etc/config.ini
```

Note that `numactl` still allows the individual threads to be scheduled on any available CPU thread on that NUMA node. You might want to find the process ID-s of those workers and pin them to specific threads. This is what I used during the exercise `psutil` in python is quite magical.

```python
#!/usr/bin/env python3

import psutil
import subprocess
import re
import sys
import os.path

def get_moloch_capture_parent():
    procs = {p.pid: p.info for p in psutil.process_iter(attrs=['pid', 'name', 'username'])}
    parent = {k: v for k, v in procs.items() if "moloch-capture" in v["name"]}
    parent = list(parent.values())[0]["pid"]
    parent = psutil.Process(pid=parent)
    return parent

def get_moloch_workers(parent):
    workers = parent.threads()
    workers = [w.id for w in workers]
    workers = [psutil.Process(pid=p) for p in workers]
    workers = [{"pid": p.pid, "name": p.name()} for p in workers]
    return workers

def get_numa_cores(node):
    numa = subprocess.run(['numactl', '--hardware'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    numa = numa.split("\n")
    numa = [v.split(":")[1].strip() for v in numa if "node {} cpus:".format(NODE) in v][0]
    numa = numa.split()
    numa = [int(v) for v in numa]
    return numa

NODE=0
CAP_IFACE="$IFACE_EXT"

if __name__ == "__main__":

    numa = get_numa_cores(NODE)

    intr_thread = numa[0]
    cap_thread = numa[1]
    worker_threads = numa[2:]

    cap_pattern = re.compile("^moloch-(?:capture|simple|af\d+-\d+)$")
    pkt_pattern = re.compile("^moloch-pkt\d+$")

    parent = get_moloch_capture_parent()
    workers = get_moloch_workers(parent)

    cap_threads = [t for t in workers if cap_pattern.match(t["name"])]
    pkt_threads = [t for t in workers if pkt_pattern.match(t["name"])]

    if len(pkt_threads) > len(worker_threads):
        print("Too many moloch workers for {} cpu threads".format(len(worker_threads)))
        sys.exit(1)

    for thread in cap_threads:
        subprocess.call(['/usr/bin/sudo', 'taskset', '-pc', str(cap_thread), str(thread["pid"])])

    for i, thread in enumerate(pkt_threads):
        subprocess.call(['/usr/bin/sudo', 'taskset', '-pc', str(worker_threads[i]), str(thread["pid"])])

    lines = []
    with open("/proc/interrupts", "rb") as f:
        lines = [l.decode().split(":")[0].lstrip() for l in f if CAP_IFACE in l.decode()]

    if len(lines) == 0 or len(lines) > 1:
        print("found {} irq for {}, should be 1".format(len(lines), CAP_IFACE))
        sys.exit(1)

    irq = lines[0]
    irq = os.path.join('/proc/irq', str(irq), 'smp_affinity_list')

    subprocess.Popen(['/usr/bin/sudo /bin/bash -c \'echo {} > {}\''.format(intr_thread, irq)], shell=True)
```

Finally, you can isolate specific CPU cores from kernel. Linux will no longer schedule anything on them. But you can assign any process you want there. Might be a good idea if you are not planning to run any other process on those cores anyway. Might be overkill if you are not experiencing *that* much traffic (you have to update boot loader params and reboot the machine).

```
GRUB_CMDLINE_LINUX_DEFAULT="processor.max_cstate=3 intel_idle.max_cstate=3 apparmor=0 mce=ignore_ce isolcpus=17-31"
```

## Tasks

 * Isolate 2 cores from your vagrant box;
  * Start moloch capture with 2 packet threads;
  * Pin each worker to an isolated CPU thread;
  * write a python script that identifies the moloch worker thread process ID-s;
 * Fix the moloch-capture service, so it would always be bound to same NUMA node as your capture NIC (yes, I know, there is only 0 in a VM);
 * Make sure that viewer and WISE do not steal CPU time from those workers;
 * Make sure that your elasticsearch instance does not steal CPU time from Moloch workers (hint - grep in docker cli options);
