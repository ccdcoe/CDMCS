# Lua scripting

> Sometimes built-in functionality is not enough

 * <https://suricata.readthedocs.io/en/latest/lua/lua-usage.html>
 * <https://suricata.readthedocs.io/en/latest/lua/lua-functions.html#lua-functions>
 * <https://suricata.readthedocs.io/en/latest/lua/index.html>
 * <https://suricata.readthedocs.io/en/latest/output/lua-output.html>
 * <https://suricata.readthedocs.io/en/latest/rules/rule-lua-scripting.html?highlight>
 * <https://luajit.org/>
 * <http://www.lua.org/pil/contents.html#P1>

## Lua support

Make sure that lua is actually compiled into suricata.

```
suricata --build-info | grep lua
  LUA support:                             yes, through luajit
  libluajit:                               yes
```

## Lua vs luajit

Lua is a dynamic interpreted language that would otherwise have to be evaluated in runtime. Not ideal for network traffic analysis where every CPU cycle matters. Just-in-time compilation dynamically evaluates code in runtime and compiles or recompiles it into optimized version of bytecode to gain significant speed advantage.

Note that luajit is a separate project from regular interpreted Lua. At the time of writing this, luajit only supports Lua 5.1 features while the latest is 5.3. Keep this in mind when installing packages as module written for latest interpreted lua may use language featrues not available in luajit.

## Setting up lua

You can install lua, luajit and luarocks (lua package manager) from your distribution repos, but keep in mind that luajit features are mostly frozen to 5.1. Thus, installing luarocks from package manager might default to newest versions.

```
apt-cache policy luajit
luajit:
  Installed: 2.1.0~beta3+dfsg-5.1
  Candidate: 2.1.0~beta3+dfsg-5.1
  Version table:
 *** 2.1.0~beta3+dfsg-5.1 500
        500 http://archive.ubuntu.com/ubuntu bionic/universe amd64 Packages
        100 /var/lib/dpkg/status
```
```
apt-cache policy lua5.1
lua5.1:
  Installed: (none)
  Candidate: 5.1.5-8.1build2
  Version table:
     5.1.5-8.1build2 500
        500 http://archive.ubuntu.com/ubuntu bionic/universe amd64 Packages
```
```
apt-cache policy lua5.3
lua5.3:
  Installed: (none)
  Candidate: 5.3.3-1
  Version table:
     5.3.3-1 500
        500 http://archive.ubuntu.com/ubuntu bionic/universe amd64 Packages

```

Some distributions provide luarocks for multiple lua versions. Others (like Ubuntu) dont. Building might be a better idea if using JIT.

```
wget http://luarocks.github.io/luarocks/releases/luarocks-3.0.4.tar.gz
tar -xzf luarocks-3.0.4.tar.gz
```

Luarocks can be configured for specific lua versions when building from source. See `configure --help` for more.

```
cd luarocks-3.0.4
./configure --lua-version=5.1
make
make install
```

Use `sudo` as needed.
