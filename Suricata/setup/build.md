# Building Suricata from source

see
* http://suricata.readthedocs.io/en/latest/install.html#source
* http://pevma.blogspot.se/2013/12/suricata-cocktails-handy-one-liners.html
* https://github.com/obsrvbl/suricata-service
* https://github.com/jasonish/suricata-rpms

## Dependencies

```
sudo apt-get -y install \
libpcre3 \
libpcre3-dbg \
libpcre3-dev \
build-essential \
autoconf \
automake \
libtool \
libpcap-dev \
libnet1-dev \
libyaml-0-2 \
libyaml-dev \
pkg-config \
zlib1g \
zlib1g-dev \
libcap-ng-dev \
libcap-ng0 \
make \
libmagic-dev
```

Or the lazy way to get most of them:

```
sudo apt-get build-dep suricata
```

## Searching for packages

```
sudo apt-cache search pcre
```

```
sudo apt-cache policy libpcre3-dev
```

## get the source
```
git clone https://github.com/OISF/suricata && cd suricata && git checkout tags/suricata-4.0.3
```

```
cd suricata
git clone https://github.com/OISF/libhtp.git -b 0.5.x
```
## configure, make install

```
./autogen.sh
```

```
./configure
```

### find your problems (also applies to make later down the line)
```
./configure  > /dev/null 2> ../error.log
```

* [configure --help](ConfigureHelp.md)
* [configure --enable-profiling --enable-luajit](ConfigureProfilingLuaJit.md)

## compile
```
make
```

```
sudo make install
```

* [make install-conf](MakeInstallConf.md)
* [make install-full](MakeInstallFull.md)

```
sudo ldconfig
```

```
suricata -V
```

## test that it works

### read a random pcap

```
suricata -c /etc/suricata/suricata.yaml -vvv -r /vagrant/test.pcap
```

### find the logging dir, check logs

```
ls -lah `grep default-log-dir: /etc/suricata/suricata.yaml | cut -d ":" -f2`
```

## Uninstall and cleaning up 

```
sudo make uninstall
make clean
make distclean
```

----
next -> [Exercises](exercises.md)
