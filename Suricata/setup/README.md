# Build and initial setup

## Build

see
* http://suricata.readthedocs.io/en/latest/install.html#source

### General build concepts

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

### Get the suricata source

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
git checkout suricata-4.1.2
```

HTTP parsing library `libhtp` is maintained in separate repository and must be cloned into main Suricata directory.

```
git clone https://github.com/OISF/libhtp -b 0.5.x
cd libhtp
git checkout 0.5.29
cd ..
```
