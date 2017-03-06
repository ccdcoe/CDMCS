# ./configure --enable-profiling --enable-luajit

* apt-get install libluajit-5.1-dev
* apt-get install libjansson-dev

```
root@secx:/home/student/oisf# ./configure --enable-profiling --enable-luajit
checking whether make supports nested variables... yes


...

checking that generated files are newer than configure... done
configure: creating ./config.status
config.status: creating htp/htp_version.h
config.status: creating Makefile
config.status: creating htp.pc
config.status: creating htp/Makefile
config.status: creating test/Makefile
config.status: creating docs/Makefile
config.status: creating htp_config_auto_gen.h
config.status: htp_config_auto_gen.h is unchanged
config.status: executing depfiles commands
config.status: executing libtool commands

Suricata Configuration:
  AF_PACKET support:                       yes
  PF_RING support:                         no
  NFQueue support:                         no
  NFLOG support:                           no
  IPFW support:                            no
  Netmap support:                          no
  DAG enabled:                             no
  Napatech enabled:                        no

  Unix socket enabled:                     yes
  Detection enabled:                       yes

  libnss support:                          no
  libnspr support:                         no
  libjansson support:                      yes
  hiredis support:                         no
  Prelude support:                         no
  PCRE jit:                                yes
  LUA support:                             yes, through luajit
  libluajit:                               yes
  libgeoip:                                no
  Non-bundled htp:                         no
  Old barnyard2 support:                   no
  CUDA enabled:                            no

  Suricatasc install:                      yes

  Unit tests enabled:                      no
  Debug output enabled:                    no
  Debug validation enabled:                no
  Profiling enabled:                       yes
  Profiling locks enabled:                 no
  Coccinelle / spatch:                     no

Generic build parameters:
  Installation prefix:                     /usr/local
  Configuration directory:                 /usr/local/etc/suricata/
  Log directory:                           /usr/local/var/log/suricata/

  --prefix                                 /usr/local
  --sysconfdir                             /usr/local/etc
  --localstatedir                          /usr/local/var

  Host:                                    x86_64-unknown-linux-gnu
  Compiler:                                gcc (exec name) / gcc (real)
  GCC Protect enabled:                     no
  GCC march native enabled:                yes
  GCC Profile enabled:                     no
  Position Independent Executable enabled: no
  CFLAGS                                   -g -O2 -march=native
  PCAP_CFLAGS                               -I/usr/include
  SECCFLAGS                                

To build and install run 'make' and 'make install'.

You can run 'make install-conf' if you want to install initial configuration
files to /usr/local/etc/suricata/. Running 'make install-full' will install configuration
and rules and provide you a ready-to-run suricata.

To install Suricata into /usr/bin/suricata, have the config in
/etc/suricata and use /var/log/suricata as log dir, use:
./configure --prefix=/usr/ --sysconfdir=/etc/ --localstatedir=/var/
```
