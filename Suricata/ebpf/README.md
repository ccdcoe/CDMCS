# eBPF and XDP

See
* Documentation: https://suricata.readthedocs.io/en/latest/capture-hardware/ebpf-xdp.html
* Talk on Suricata, XDP and eBPF: https://home.regit.org/~regit/suricata-ebpf.pdf
* BPF cli wrapper: https://github.com/StamusNetworks/bpfctrl.git

**Vagrant env has most libraries and tools in `/data` folder.** Please use `root` user for the duration of this exercise. Many things may otherwise be installed locally for regular user and debugging those issues is not the purpose of this exercise.

**Commands in this README serve illustrative purpose**. Please follow official Suricata documentation for updated reference. 

## Building a eBPF enable Suricata

Suricata uses libbpf to interact with eBPF. The library is available at https://github.com/libbpf/libbpf
and is already cloned in the libbpf directory inside the `/data` directory. Build it from
the `src` directory with a traditional

```
make
make install
```

To enable eBPF support you need to pass a series of flags to suricata configure:

```
./configure --enable-ebpf --enable-ebpf-build CC=clang-6.0
```

You can then build and install the software 

```
make -j4
make install
make install-conf
```

## Setup

### System
To used pinned maps, you first have to mount the `bpf` pseudo filesystem ::

```
sudo mount -t bpf none /sys/fs/bpf
```

### Suricata

Suricata configuration file section on af-packet needs to be updated to have the eBPF filter
setup and pinned maps activated:

```
af-packet:
  - interface: enp0s8
    ebpf-filter-file: /home/vagrant/suricata/ebpf/filter.bpf
    pinned-maps: true
```

By pointing directly to the eBPF filter in the source tree we will be able to update it easily later.

### CLI tooling

See [bfpctrl git page](https://github.com/StamusNetworks/bpfctrl.git) for setup instructions. However, do not clone entire linux source repository as instructed in readme. It is big. An unpacked kernel tarball is already prepared in `/data`.

## Usage

### Setting things up 

Find an IP address you can communicate with on primary vagrant box interface and add it to the block list
with `bpfctrl`.

The syntax is `bpfctrl -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop ipv4 --add 1.2.3.4=1` where `1.2.3.4` is the IP to add and `bpfctrl -m /sys/fs/bpf/suricata-wlp4s0-ipv4_drop ipv4 --remove 1.2.3.4` to remove.

Once done, verify no traffic is seen anymore with this IP address.

One can use `suricatasc` to get interface statistics and/or analyze eve.json output
for significative events.

### Invert the logic

Update `filter.c` to get a pass list instead of a block list. Test it by checking traffic really
start when IP are added.

### Add some more logic

Update `filter.c` to only accept traffic on the port 22 for the IP addresses in the pass list.

---

[back](/Suricata)
