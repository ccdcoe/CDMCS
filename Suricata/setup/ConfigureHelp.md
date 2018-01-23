# ./configure --help

```
root@suricata:~/oisf# ./configure --help
`configure' configures suricata 4.0dev to adapt to many kinds of systems.

Usage: ./configure [OPTION]... [VAR=VALUE]...

To assign environment variables (e.g., CC, CFLAGS...), specify them as
VAR=VALUE.  See below for descriptions of some of the useful variables.

Defaults for the options are specified in brackets.

Configuration:
  -h, --help              display this help and exit
      --help=short        display options specific to this package
      --help=recursive    display the short help of all the included packages
  -V, --version           display version information and exit
  -q, --quiet, --silent   do not print `checking ...' messages
      --cache-file=FILE   cache test results in FILE [disabled]
  -C, --config-cache      alias for `--cache-file=config.cache'
  -n, --no-create         do not create output files
      --srcdir=DIR        find the sources in DIR [configure dir or `..']

Installation directories:
  --prefix=PREFIX         install architecture-independent files in PREFIX
                          [/usr/local]
  --exec-prefix=EPREFIX   install architecture-dependent files in EPREFIX
                          [PREFIX]

By default, `make install' will install all the files in
`/usr/local/bin', `/usr/local/lib' etc.  You can specify
an installation prefix other than `/usr/local' using `--prefix',
for instance `--prefix=$HOME'.

For better control, use the options below.

Fine tuning of the installation directories:
  --bindir=DIR            user executables [EPREFIX/bin]
  --sbindir=DIR           system admin executables [EPREFIX/sbin]
  --libexecdir=DIR        program executables [EPREFIX/libexec]
  --sysconfdir=DIR        read-only single-machine data [PREFIX/etc]
  --sharedstatedir=DIR    modifiable architecture-independent data [PREFIX/com]
  --localstatedir=DIR     modifiable single-machine data [PREFIX/var]
  --runstatedir=DIR       modifiable per-process data [LOCALSTATEDIR/run]
  --libdir=DIR            object code libraries [EPREFIX/lib]
  --includedir=DIR        C header files [PREFIX/include]
  --oldincludedir=DIR     C header files for non-gcc [/usr/include]
  --datarootdir=DIR       read-only arch.-independent data root [PREFIX/share]
  --datadir=DIR           read-only architecture-independent data [DATAROOTDIR]
  --infodir=DIR           info documentation [DATAROOTDIR/info]
  --localedir=DIR         locale-dependent data [DATAROOTDIR/locale]
  --mandir=DIR            man documentation [DATAROOTDIR/man]
  --docdir=DIR            documentation root [DATAROOTDIR/doc/suricata]
  --htmldir=DIR           html documentation [DOCDIR]
  --dvidir=DIR            dvi documentation [DOCDIR]
  --pdfdir=DIR            pdf documentation [DOCDIR]
  --psdir=DIR             ps documentation [DOCDIR]

Program names:
  --program-prefix=PREFIX            prepend PREFIX to installed program names
  --program-suffix=SUFFIX            append SUFFIX to installed program names
  --program-transform-name=PROGRAM   run sed PROGRAM on installed program names

System types:
  --build=BUILD     configure for building on BUILD [guessed]
  --host=HOST       cross-compile to build programs to run on HOST [BUILD]

Optional Features:
  --disable-option-checking  ignore unrecognized --enable/--with options
  --disable-FEATURE       do not include FEATURE (same as --enable-FEATURE=no)
  --enable-FEATURE[=ARG]  include FEATURE [ARG=yes]
  --enable-silent-rules   less verbose build output (undo: "make V=1")
  --disable-silent-rules  verbose build output (undo: "make V=0")
  --enable-dependency-tracking
                          do not reject slow dependency extractors
  --disable-dependency-tracking
                          speeds up one-time build
  --enable-shared[=PKGS]  build shared libraries [default=yes]
  --enable-static[=PKGS]  build static libraries [default=yes]
  --enable-fast-install[=PKGS]
                          optimize for fast installation [default=yes]
  --disable-libtool-lock  avoid locking (might break parallel builds)
  --enable-python         Enable python
  --disable-largefile     omit support for large files
  --enable-afl            Enable AFL fuzzing logic]
  --disable-threading-tls Disable TLS (thread local storage)
  --enable-gccprotect     Detect and use gcc hardening options
  --enable-gccprofile     Enable gcc profile info i.e -pg flag is set
  --enable-gccmarch-native
                          Enable gcc march=native gcc 4.2 and later only
  --enable-unittests      Enable compilation of the unit tests
  --enable-old-barnyard2  Use workaround for old barnyard2 in unified2 output
  --enable-debug          Enable debug output
  --enable-debug-validation
                          Enable (debug) validation code output
  --enable-profiling      Enable performance profiling
  --enable-profiling-locks
                          Enable performance profiling for locks
  --enable-ipfw           Enable FreeBSD IPFW support for inline IDP
  --disable-coccinelle    Disable coccinelle QA steps during make check
  --disable-detection     Disable Detection Modules
  --enable-unix-socket    Enable unix socket [default=test]
  --enable-nflog          Enable libnetfilter_log support
  --enable-nfqueue        Enable NFQUEUE support for inline IDP
  --enable-prelude        Enable Prelude support for alerts
  --enable-pfring         Enable Native PF_RING support
  --enable-af-packet      Enable AF_PACKET support [default=yes]
  --enable-netmap         Enable Netmap support
  --enable-non-bundled-htp
                          Enable the use of an already installed version of
                          htp
  --enable-cuda           Enable experimental CUDA pattern matching
  --enable-dag            Enable DAG capture
  --enable-libmagic       Enable libmagic support [default=yes]
  --enable-napatech       Enabled Napatech Devices
  --enable-lua            Enable Lua support
  --enable-luajit         Enable Luajit support
  --enable-geoip          Enable GeoIP support
  --enable-pie            Enable compiling as a position independent
                          executable
  --enable-hiredis        Enable Redis support

Optional Packages:
  --with-PACKAGE[=ARG]    use PACKAGE [ARG=yes]
  --without-PACKAGE       do not use PACKAGE (same as --with-PACKAGE=no)
  --with-pic[=PKGS]       try to use only PIC/non-PIC objects [default=use
                          both]
  --with-aix-soname=aix|svr4|both
                          shared library versioning (aka "SONAME") variant to
                          provide on AIX, [default=aix].
  --with-gnu-ld           assume the C compiler uses GNU ld [default=no]
  --with-sysroot[=DIR]    Search for dependent libraries within DIR (or the
                          compiler's sysroot if not specified).
  --with-libpcre-includes=DIR  libpcre include directory
  --with-libpcre-libraries=DIR    libpcre library directory
  --with-libhs-includes=DIR  libhs include directory
  --with-libhs-libraries=DIR    libhs library directory
  --with-libyaml-includes=DIR  libyaml include directory
  --with-libyaml-libraries=DIR    libyaml library directory
  --with-libpthread-includes=DIR  libpthread include directory
  --with-libpthread-libraries=DIR    libpthread library directory
  --with-libjansson-includes=DIR  libjansson include directory
  --with-libjansson-libraries=DIR    libjansson library directory
  --with-libnfnetlink-includes=DIR  libnfnetlink include directory
  --with-libnfnetlink-libraries=DIR    libnfnetlink library directory
  --with-libnetfilter_queue-includes=DIR  libnetfilter_queue include directory
  --with-libnetfilter_queue-libraries=DIR    libnetfilter_queue library directory
  --with-netfilterforwin-includes=DIR  netfilterforwin include directory
  --with-libnetfilter_log-includes=DIR  libnetfilter_log include directory
  --with-libnetfilter_log-libraries=DIR    libnetfilter_log library directory
  --with-libprelude-prefix=PFX
                          Prefix where libprelude is installed (optional)
  --with-libnet-includes=DIR     libnet include directory
  --with-libnet-libraries=DIR    libnet library directory
  --with-libpcap-includes=DIR  libpcap include directory
  --with-libpcap-libraries=DIR    libpcap library directory
  --with-libpfring-includes=DIR  libpfring include directory
  --with-libpfring-libraries=DIR    libpfring library directory
  --with-netmap-includes=DIR netmap include directory
  --with-libhtp-includes=DIR  libhtp include directory
  --with-libhtp-libraries=DIR    libhtp library directory
  --with-cuda-includes=DIR  cuda include directory
  --with-cuda-libraries=DIR    cuda library directory
  --with-cuda-nvcc=DIR  cuda nvcc compiler directory
  --with-libcap_ng-includes=DIR  libcap_ng include directory
  --with-libcap_ng-libraries=DIR    libcap_ng library directory
  --with-dag-includes=DIR  dagapi include directory
  --with-dag-libraries=DIR  dagapi library directory
  --with-libnspr-includes=DIR  libnspr include directory
  --with-libnspr-libraries=DIR    libnspr library directory
  --with-libnss-includes=DIR  libnss include directory
  --with-libnss-libraries=DIR    libnss library directory
  --with-libmagic-includes=DIR  libmagic include directory
  --with-libmagic-libraries=DIR    libmagic library directory
  --with-napatech-includes=DIR   napatech include directory
  --with-napatech-libraries=DIR  napatech library directory
  --with-liblua-includes=DIR  liblua include directory
  --with-liblua-libraries=DIR    liblua library directory
  --with-libluajit-includes=DIR  libluajit include directory
  --with-libluajit-libraries=DIR    libluajit library directory
  --with-libgeoip-includes=DIR  libgeoip include directory
  --with-libgeoip-libraries=DIR    libgeoip library directory
  --with-libhiredis-includes=DIR  libhiredis include directory
  --with-libhiredis-libraries=DIR    libhiredis library directory

Some influential environment variables:
  CC          C compiler command
  CFLAGS      C compiler flags
  LDFLAGS     linker flags, e.g. -L<lib dir> if you have libraries in a
              nonstandard directory <lib dir>
  LIBS        libraries to pass to the linker, e.g. -l<library>
  CPPFLAGS    (Objective) C/C++ preprocessor flags, e.g. -I<include dir> if
              you have headers in a nonstandard directory <include dir>
  LT_SYS_LIBRARY_PATH
              User-defined run-time library search path.
  CPP         C preprocessor
  PKG_CONFIG  path to pkg-config utility
  PKG_CONFIG_PATH
              directories to add to pkg-config's search path
  PKG_CONFIG_LIBDIR
              path overriding pkg-config's built-in search path
  LIBPCREVERSION_CFLAGS
              C compiler flags for LIBPCREVERSION, overriding pkg-config
  LIBPCREVERSION_LIBS
              linker flags for LIBPCREVERSION, overriding pkg-config
  libhs_CFLAGS
              C compiler flags for libhs, overriding pkg-config
  libhs_LIBS  linker flags for libhs, overriding pkg-config
  libnetfilter_queue_CFLAGS
              C compiler flags for libnetfilter_queue, overriding pkg-config
  libnetfilter_queue_LIBS
              linker flags for libnetfilter_queue, overriding pkg-config
  libhtp_CFLAGS
              C compiler flags for libhtp, overriding pkg-config
  libhtp_LIBS linker flags for libhtp, overriding pkg-config
  LIBHTPMINVERSION_CFLAGS
              C compiler flags for LIBHTPMINVERSION, overriding pkg-config
  LIBHTPMINVERSION_LIBS
              linker flags for LIBHTPMINVERSION, overriding pkg-config
  LIBHTPDEVVERSION_CFLAGS
              C compiler flags for LIBHTPDEVVERSION, overriding pkg-config
  LIBHTPDEVVERSION_LIBS
              linker flags for LIBHTPDEVVERSION, overriding pkg-config
  PYTHON      the Python interpreter
  libnspr_CFLAGS
              C compiler flags for libnspr, overriding pkg-config
  libnspr_LIBS
              linker flags for libnspr, overriding pkg-config
  libnss_CFLAGS
              C compiler flags for libnss, overriding pkg-config
  libnss_LIBS linker flags for libnss, overriding pkg-config
  LUA_CFLAGS  C compiler flags for LUA, overriding pkg-config
  LUA_LIBS    linker flags for LUA, overriding pkg-config
  LUAJIT_CFLAGS
              C compiler flags for LUAJIT, overriding pkg-config
  LUAJIT_LIBS linker flags for LUAJIT, overriding pkg-config

Use these variables to override the choices made by `configure' or to help
it to find libraries and programs with nonstandard names/locations.

Report bugs to the package provider.
```
