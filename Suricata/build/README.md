# Building Suricata

This section assumes that user is already familiar with using prebuilt Suricata on CLI, parsing PCAP files and loading rulesets. It **does not assume** knowledge about `suricata.yaml`, other than it's existence in filesystem.

Also, this section is **not** a step-by-step. But all needed information is here.

See
* http://suricata.readthedocs.io/en/latest/install.html#source

## General build concepts

Building Suricata is no different from than 99% other software written in C. You have you dependency hunt, configure scripts, compiling, installing, etc.

If a dependency is missing, search for it using whatever package manager your system has.

```
sudo apt-cache search pcre
```

Building packages requires development headers which are packaged separate from main libraries on Ubuntu/Debian systems. For example, if `configure` fails due to missing pcre3 dependency then it will likely tell you correct package name. You can inspect and install that package with following command.

```
sudo apt-cache policy libpcre3-dev
sudo apt-get install libpcre3-dev
```

Configure script itself is not written. It's generated with `automake` toolbox. So you will not find `configure` when cloning Suricata repo. Following command needs to be run first.

```
./autogen.sh
```

Configure script sets up build parameters before compiling. **It has a lot of options.** Use `--help` to see them.

```
./configure --help
```

That help can easily be grepped if you want to make sure you enable specific features.

```
./configure --help | grep -i redis
```

A good practice is to prefix build root with custom directory to keep the system clean. **That directory is entirely up to you**. Keep in mind that you **don't need superuser privileges at all for configuring and compiling**. And **you only need superuser privileges for `make install` if using a system folder**.

**Tip** - use multiple clean folders to test different deploy configs.

```
./configure --prefix=$INSTALL_DIR
```

Then compile and install the software. `make` will work locally while `make install` will place compiled binaries to `--prefix` value in prior step. If prefix was not defined, then please refer to `configure` output to see the destination folders.

```
make
```
```
make install
```

`-j` flag can be used to make compilation faster by using more CPU threads. Following command would use 4 threads.

```
make -j 4
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

Most important, Suricata needs **cbindgen** package for interfacing C code with Rust. It can be installed with `cargo` or with package manager.

## Build suricata

```
./autogen.sh
```

Configure the software to local build directory. `--prefix` is the **install directory**, **DO NOT USE THE SAME FOLDER WHERE YOU CLONED THE CODE!**.

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

Install default configuraiton file.

```
make install-conf
```

Alternatively, `make install-full` will combine `make install`, `make install-conf` and will download latest et/open ruleset. However, student should already familiar with working with bare Suricata and managing rulesets for themselves. So monolithic deploy is not needed.

```
<prefix>/bin/suricata -V
```

If you have already generated different binaries in different prefix directories, you might have forgot the specific configuration options of a previous build. You can check that from the binary.

```
<prefix>/bin/suricata --build-info
```

## Debugging missing libraries

You may experience library errors if you built dependencies by hand. For example, if compiling with hyperscan support with custom-built hyperscan package, the you might run into this.

```
./bin/suricata: error while loading shared libraries: libhs.so.5: cannot open shared object file: No such file or directory
```

Use `ldd` command to debug this issue. It lists out all shared dependencies along with where exactly the Suricata is searching for the libs.

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

 * Build your own suricata with following features:
  * async redis;
  * hyperscan;
  * LuaJIT;
 * Build suricata **to another install directory** with ruleset profiling enabled
