# Building hyperscan

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

Note that suricata may not start up with this config, as system runtime is unaware of custom shared library directory.

