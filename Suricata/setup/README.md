# Build

See
* http://suricata.readthedocs.io/en/latest/install.html#source

## General build concepts

Searching for packages

```
sudo apt-cache search pcre
```

Building packages requires development headers which are packaged separate from main libraries on Ubuntu/Debian systems.

```
sudo apt-cache policy libpcre3-dev
```

If configure scripts are missing, then they may need to be generated.

```
./autogen.sh
```

Configure script sets up build parameters before compiling. 

```
./configure --help
```

A good practice is to prefix build root with custom directory to keep the system clean. This is arbitrary but your user must have write access to this folder. Use `sudo` when needed.

```
./configure --prefix=/home/vagrant/software
```

Then compile and install the software. `make` will work locally while `make install` will place compiled binaries to `--prefix` value in prior step. If prefix was not defined, then please refer to `configure` output to see the destination folders.

```
make && make install
```

It is normal to mess up while building. Libraries may be missing, configure flags omitted, wrong versions in the system, etc.  First, remove any files from `make install` step.

```
make uninstall
```

Then clean up local compiled files.

```
make clean
```

Finally, remove configuration options.

```
make distclean
```

Note that available make subcommands are listed in `Makefile`. Depending on project, some commands may be missing. That's why `--prefix` is a good idea for cleaning up. Furthermore, some build options may conflict with each other, others are experimental. You may want to do version rollover as opposed to in-place upgrade, etc. In other words, installing multiple builds may be easier than uninstalling.

## Get the suricata source

Pull the latest from github. Note that git commands are local to working directory.

```
git clone https://github.com/OISF/suricata suricata-build
cd suricata-build
```

Optionally check out a concrete version. Latest dev build may have issues (though, it may also fix them). See all tags and branches.

```
git tag
git branch -a
```

```
git checkout $VERSION
```

HTTP parsing library `libhtp` is maintained in separate repository and must be cloned into main Suricata directory.

```
git clone https://github.com/OISF/libhtp -b 0.5.x
cd libhtp
git checkout $VERSION
cd ..
```

## Basic tools and build dependencies

First, make sure you have software needed for building suricata. Apply `sudo` where and when needed.

```
apt-get update && apt-get -y install \
build-essential \
autoconf \
automake \
libtool \
pkg-config \
make \
curl \
wget \
git \
unzip
```

Then install development headers for configure options. Note that this list is incomplete on purpose and only contains bare minimums.Finding correct libraries is left as an exercise for the reader. Refer to official documentation and `./configure` output when searching for libraries.

```
apt-get update && apt-get -y install \
libpcre3 \
libpcre3-dbg \
libpcre3-dev \
libpcap-dev \
libnet1-dev \
libyaml-0-2 \
libyaml-dev \
libmagic-dev \
zlib1g \
zlib1g-dev \
libcap-ng-dev \
libcap-ng0
```

## Rust

 * https://doc.rust-lang.org/book/index.html
 * https://rustup.rs/
 * https://www.rust-lang.org/tools/install

Suricata is written in C, but is gradually migrating to Rust, a low level systems programming language built for memory safety. New parsers and output modules are now written in Rust and old ones are being rewritten. Since 4.1, Rust is now enabled by default when configuring Suricata and should no longer be considered an experimental optional feature.

The Rust method for installing `rust` and its package manger `cargo` is to use *rustup* toolchain that installs everything under local user home directory.

```
curl https://sh.rustup.rs -sSf | sh
```

Then make sure that rust binaries are in your `PATH`. Run the following command in console, or append to `~/.bashrc` or `~/.zshrc` or `~/.profile`, depending on shell choice.

```
export PATH="$HOME/.cargo/bin:$PATH"
```

## Building hyperscan

**Only do this if you build Suricata for performance on a platform that does not provide hyperscan binary packages. Building it will take long time and will melt your laptop! This section is only for reference!**

 * https://01.org/hyperscan
 * https://github.com/intel/hyperscan

In addition to prior build tools, install cmake and friends.

```
apt-get install -y cmake ragel libboost-all-dev sqlite3
```

Grab the source.

```
git clone https://github.com/intel/hyperscan /home/vagrant/hyperscan-build
cd /home/vagrant/hyperscan-build
git checkout $VERSION
```

Build locally using cmake.

```
cmake -DCMAKE_INSTALL_PREFIX=/home/vagrant/Libraries -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_STATIC_AND_SHARED=1
```

Then compile and install. Parallelize to whatever number of CPU threads you have and go grab a coffee. This may take a while.

```
make -j4 && make install
```

If on laptop, put it down for health and safety and make sure it is not on battery power.

```
coretemp-isa-0000
Adapter: ISA adapter
Package id 0: +100.0°C  (high = +84.0°C, crit = +100.0°C)
Core 0:        +96.0°C  (high = +84.0°C, crit = +100.0°C)
Core 1:       +100.0°C  (high = +84.0°C, crit = +100.0°C)
Core 2:        +99.0°C  (high = +84.0°C, crit = +100.0°C)
Core 3:        +92.0°C  (high = +84.0°C, crit = +100.0°C)

acpitz-acpi-0
Adapter: ACPI interface
temp1:        +98.0°C  (crit = +200.0°C)

thinkpad-isa-0000
Adapter: ISA adapter
fan1:        3478 RPM
```

Finally, configure suricata with hyperscan library directories. See `cmake` flags in prior commands.

```
cd <suri-build-dir>
./configure --prefix=<suri-install-dir> --with-libhs-includes=/home/vagrant/Libraries/include/hs  --with-libhs-libraries=/home/vagrant/Libraries/lib
```

Note that suricata may not start up with this config, as system runtime is unaware of custom shared library directory. See next section for debug.

## Build suricata

Configure the software to local build directory.

```
cd <repo-clone-dir>
./configure --prefix=$HOME/meerkat/$VERSION
```

Compile using 4 threads.

```
make -j4
```

Install the software 

```
make install
ls -lah $HOME/meerkat/$VERSION
```

Install default config file.

```
make install-conf
```

Alternatively, `make install-full` will combine `make install`, `make install-conf` and will download latest et/open ruleset. However, this is not needed for this exercise as we will manage rules separately.

```
<prefix>/bin/suricata -V
```

You may experience library errors of you built dependencies by hand. For example, if you followed last section, you will now see this:

```
./bin/suricata: error while loading shared libraries: libhs.so.5: cannot open shared object file: No such file or directory
```

Use `ldd` command to debug this issue.

```
vagrant@buildSuricata:~/suricata/4.1.2-cdmcs$ ldd ./bin/suricata
        linux-vdso.so.1 (0x00007fff9f318000)
        libhtp.so.2 => /home/vagrant/suricata/4.1.2-cdmcs/lib/libhtp.so.2 (0x00007fad50237000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fad50033000)
        librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007fad4fe2b000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fad4fa8d000)
        libmagic.so.1 => /usr/lib/x86_64-linux-gnu/libmagic.so.1 (0x00007fad4f86b000)
        libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fad4f666000)
        libpcap.so.0.8 => /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 (0x00007fad4f425000)
        libnet.so.1 => /usr/lib/x86_64-linux-gnu/libnet.so.1 (0x00007fad4f20b000)
        libjansson.so.4 => /usr/lib/x86_64-linux-gnu/libjansson.so.4 (0x00007fad4effd000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fad4edde000)
        libyaml-0.so.2 => /usr/lib/x86_64-linux-gnu/libyaml-0.so.2 (0x00007fad4ebc0000)
        libhs.so.5 => not found
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007fad4e94e000)
        libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007fad4e731000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007fad4e519000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fad4e128000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fad50ac7000)
```

Use `find` to locate missing files.

```
find /home/vagrant/ -type f -name 'libhs.so*'
```

Using ldconfig system-wide. Apply sudo as needed. Then repeat the prior `ldd` command. Prior `not found`.

```
echo "/home/vagrant/Libraries/lib/" > /etc/ld.so.conf.d/suri-hyperscan.conf
ldconfig
```

## Exercises

 * Build your own suricata with features needed for subsequent tasks
   * set a custom installation root of your own choosing
     * configuration directory should be placed under /vagrant/config
   * it must support the following features:
     * EVE log in JSON format
     * redis output with async support
     * lua scripting with just-in-time compiler
     * unix socket support with suricatasc utility
     * NFS logging and output
     * Rule profiling
     * MD5 and JA3 hashing
 * Build a second suricata instance with rule profiling disabled.

### testing and hints

 * https://wiki.wireshark.org/SampleCaptures#NFS_Protocol_Family
 * https://www.malware-traffic-analysis.net/2018/index.html
 * `curl testmyids.com`
 * https://github.com/OISF/suricata/blob/d05355db3d6e2752ae0582a7ea8c1a0f08bde91c/src/output-json-alert.c

# Config

 * https://suricata.readthedocs.io/en/latest/configuration/suricata-yaml.html#

```
suricata -c <config-dir>/suricata.yaml
```

If a configuration option is not specified in  the configuration file, Suricata uses its internal default configuration. Test configuration with `-T` flag.

```
suricata -T -vvv
```

Show active config parameters

```
suricata --dump-config
```

See only active configuration. `suricata.yaml` is like a documentation in itself. See the file without comments.

```
grep -v -E '^\s*#' /etc/suricata/suricata.yaml
# remove empty lines as well
grep -v -E '^\s*#' /etc/suricata/suricata.yaml | grep -v '^$'
sed -i -e 's/#.*$//' -e '/^\s*$/d' /etc/suricata/suricata.yaml
```

## Managing rules

 * https://suricata.readthedocs.io/en/latest/rule-management/suricata-update.html
 * https://suricata-update.readthedocs.io/en/latest/

```
apt-get install python3-pip
python3 -m pip install --upgrade --user suricata-update
```

Official rule update tool is a python script.

```
/home/vagrant/.local/bin/suricata-update --help
/home/vagrant/.local/bin/suricata-update list-sources
```

Enable a new rule source.

```
/home/vagrant/.local/bin/suricata-update enable-source tgreen/hunting
```

Update rules

```
/home/vagrant/.local/bin/suricata-update -D /vagrant
```

Rule directory is usually defined in `suricata.yaml`.

```
default-rule-path: /var/lib/suricata/rules
rule-files:
 -  suricata.rules
```

## Reloading rules via unix-socket

Suricata rule database can be updated without system restart, but this requires `unix-command` to be enabled in `suricata.yaml`.

```
unix-command:
  enabled: auto
  #filename: custom.socket
```

Make sure you have read permissions for socket, or just use `sudo` as needed.

```
suricatasc -c "reload-rules"
```

Then add update command with reload to periodic cron task.

### Exercise

* Set up periodic rule update. Rules should be located in `/vagrant/var`. Following rulesets should be activated:
  * `et/open`
  * `oisf/trafficid`
  * `ptresearch/attackdetection`
  * `tgreen/hunting`
  * All suricata rulesets from [sslbl](https://sslbl.abuse.ch/blacklist/)
* Set up a web server for custom rules (use the ones you have already written or create some new ones);
  * Hint - you can use [official nginx docker container](https://hub.docker.com/_/nginx) to quickly create a simple web server.
  * Add your custom rule source to periodic updates;
* Disable following rules:
  * Outbound Curl user-agent;
  * apt and yum package management;
  * Unix and BSD ping;
  * SID `906200077`, `906200082`, `906200087`, `906200088`, `906200048`, `906200047´, ´906200038`, `906200015`;

## Packet acquisition

Modern method for getting packets from kernel space to suricata is `af-packet`. Interface can be defined as command line flag.

```
suricata --af-packet=enp0s3 -S /vagrant/var/rules/suricata.rules  -l /home/vagrant/logs -D -vvv
```

A proper way would be to define interfaces in `suricata.yaml`. Note that `cluster-id` values should be unique.

```
af-packet:
  - interface: enp0s3
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: enp0s8
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
```

Then run suricata with empty `--af-packet` flag.

```
suricata --af-packet -S /vagrant/var/rules/suricata.rules  -l /home/vagrant/logs -D -vvv
```

## Home networks

Edit `suricata.yaml` with proper network information. You should see the following in the head of the file. **Do not forget IPv6**.

```
vars:
  # more specific is better for alert accuracy and performance
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    #HOME_NET: "[192.168.0.0/16]"
    #HOME_NET: "[10.0.0.0/8]"
    #HOME_NET: "[172.16.0.0/12]"
    #HOME_NET: "any"

    EXTERNAL_NET: "!$HOME_NET"
    #EXTERNAL_NET: "any"

    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
```

These variables are used in rules to indicate perimeter directionality.

```
#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP login literal buffer overflow attempt"; flow:established,to_server; content:"LOGIN"; nocase; pcre:"/\sLOGIN\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,6298; classtype:misc-attack; sid:2101993; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
```

## Logging and EVE JSON

 * https://suricata.readthedocs.io/en/latest/output/eve/eve-json-output.html
 * https://suricata.readthedocs.io/en/latest/output/eve/eve-json-format.html
 * https://suricata.readthedocs.io/en/latest/output/eve/eve-json-examplesjq.html

When built with json support, `eve.json` should be in `default-log-dir`.

```
grep "default-log-dir" suricata.yaml
```
 
Use [jq](https://stedolan.github.io/jq/) to [verify correct output](https://suricata.readthedocs.io/en/latest/output/eve/eve-json-examplesjq.html).

### tl; dr

In short, this is your typical to-do list in `suricata.yaml` after fresh install -

 * Home nets;
 * Default log directory;
 * eve.json output;
 * af-packet input;
 * rules;
    * update;
    * Rule directory;
    * rule file;
 * run suricata with `--af-packet` argument;

### Exercises

 * Configure suricata with your Vagrant box uplink subnet as home network;
 * Run Suricata in daemon mode with up to date rules;
 * Configure `/vagrant/logs` as destination for `eve.json`;
 * Enable SIP protocol logging;
   * Test using pcaps from this site - https://wiki.wireshark.org/SampleCaptures
 * Enable ja3 and ja3s hashing support
 * Read some pcap files with non-daemonized version of suricata from [malware traffic analysis site](http://malware-traffic-analysis.net/);
   * Any pcap file is fine, it's mainly for generating some interesting data for next exercises
   * Look for zip files. Password is usually `INFECTED`

---

[back](/Suricata)
