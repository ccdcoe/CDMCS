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

### Basic tools and build dependencies

First, make sure you have software needed for building suricata.

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

### Rust

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
