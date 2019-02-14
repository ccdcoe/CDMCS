# eBPF and XDP

See
* Documentation: https://github.com/regit/suricata/blob/ebpf-xdp-update-8.2/doc/userguide/capture-hardware/ebpf-xdp.rst
* Talk on Suricata, XDP and eBPF: https://home.regit.org/~regit/suricata-ebpf.pdf

## Building a eBPF enable Suricata

Suricata uses libbpf to interact with eBPF. The library is available at https://github.com/libbpf/libbpf
and is already cloned in the libbpf directory inside the `vagrant` user home directory. Build it from
the `src` directory with a traditional

```
make
make install
```

Switch to `suricata` directory in home directory.

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

The 4.15 kernel of Ubuntu 18.04 is too old and the 4.18 kernel of Ubuntu 18.10 is buggy so we need to install
a custom kernel. To do so download the following packages:

* https://kernel.ubuntu.com/~kernel-ppa/mainline/v4.17/linux-modules-4.17.0-041700-generic_4.17.0-041700.201806041953_amd64.deb
* https://kernel.ubuntu.com/~kernel-ppa/mainline/v4.17/linux-image-unsigned-4.17.0-041700-generic_4.17.0-041700.201806041953_amd64.deb

And install them with `dpkg -i linux*deb`. Once done remove the previous kernel and reboot.

## Setup


To used pinned maps, you first have to mount the `bpf` pseudo filesystem ::

```
sudo mount -t bpf none /sys/fs/bpf
```

Suricata configuration file section on af-packet needs to be updated to have the eBPF filter
setup and pinned maps activated:

```
af-packet:
  - interface: enp0s8
    ebpf-filter-file: /home/vagrant/suricata/ebpf/filter.bpf
    pinned-maps: true
```

By pointing directly to the eBPF filter in the source tree we will be able to update it
easily later.

## Usage

### Setting things up 

Find an IP address you can communicate with on `enp0s8` and add it to the block list
with scbpf. Once done, verify no traffic is seen anymore with this IP address.

One can use `suricatasc` to get interface statistics and/or analyze eve.json output
for significative events.

### Invert the logic

Update `filter.c` to get a pass list instead of a block list. Test it by checking traffic really
start when IP are added.

### Add some more logic

Update `filter.c` to only accept traffic on the port 22 for the IP addresses in the pass list.

---

[back](/Suricata)
