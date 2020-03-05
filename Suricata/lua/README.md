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

Use `sudo` as needed. Make sure you have deps.

```
apt-get install liblua5.1-0-dev lua5.1 unzip
```

## Installing a first package

```
luarocks install --local luasocket
luarocks install --local redis-lua
```

Note that `--local` install packages into a subdir of your user.

```
vagrant@luabox:~$ ls -lah ~/.luarocks/
total 16K
drwxrwxr-x 4 vagrant vagrant 4.0K Feb  8 13:36 .
drwxr-xr-x 9 vagrant vagrant 4.0K Feb  8 13:35 ..
drwxrwxr-x 4 vagrant vagrant 4.0K Feb  8 13:36 lib
drwxrwxr-x 3 vagrant vagrant 4.0K Feb  8 13:35 share
```

This directory may not be in Lua package paths. Consider a simple script that excahges data with redis instance. First, start a redis container.

```
docker run -ti -d -p 6379:6379 redis
```

Then write a `hello_redis.lua` script.

```
local redis = require 'redis'
local client = redis.connect('192.168.10.16', 6379)
local response = client:ping()

if response == false then
	return 0
end

client:set("test:hello", "world")

local var = client:get("test:hello")
print(var)
```

Running it with `luajit` would likely result in error.


```
luajit hello_redis.lua
```
```
luajit: hello_redis.lua:1: module 'redis' not found:
        no field package.preload['redis']
        no file './redis.lua'
        no file '/usr/share/luajit-2.1.0-beta3/redis.lua'
        no file '/usr/local/share/lua/5.1/redis.lua'
        no file '/usr/local/share/lua/5.1/redis/init.lua'
        no file '/usr/share/lua/5.1/redis.lua'
        no file '/usr/share/lua/5.1/redis/init.lua'
        no file './redis.so'
        no file '/usr/local/lib/lua/5.1/redis.so'
        no file '/usr/lib/x86_64-linux-gnu/lua/5.1/redis.so'
        no file '/usr/local/lib/lua/5.1/loadall.so'
stack traceback:
        [C]: in function 'require'
        hello_redis.lua:1: in main chunk
        [C]: at 0x56251b4e41d0
```

Then execute `luarocks path --bin` command and enter its output into your shell.

```
export LUA_PATH='/home/vagrant/.luarocks/share/lua/5.1/?.lua;/home/vagrant/.luarocks/share/lua/5.1/?/init.lua;/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;./?.lua;/usr/local/lib/lua/5.1/?.lua;/usr/local/lib/lua/5.1/?/init.lua;/usr/share/lua/5.1/?.lua;/usr/share/lua/5.1/?/init.lua'
export LUA_CPATH='/home/vagrant/.luarocks/lib/lua/5.1/?.so;/usr/local/lib/lua/5.1/?.so;./?.so;/usr/lib/x86_64-linux-gnu/lua/5.1/?.so;/usr/lib/lua/5.1/?.so;/usr/local/lib/lua/5.1/loadall.so'
export PATH='/home/vagrant/.luarocks/bin:/usr/local/bin:/home/vagrant/.local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin'
```

```
vagrant@luabox:/vagrant/rules$ luajit hello_redis.lua
world
```

[See this old but decent reference for lua syntax.](http://www.lua.org/pil/contents.html#P1)

## Lua in the meerkat

Lua scripts can be called from Suricata rules or be confinuously run as output/logging module.

### Rules

 * https://suricata.readthedocs.io/en/latest/rules/rule-lua-scripting.html
 * https://suricata.readthedocs.io/en/latest/lua/index.html

As always, create a rule file or append a new rule to existing file. For example, let's create a new rule file called `lua.rules`. The following rule will trigger on all parsed TLS connections.

```
alert tls any any -> any any (msg:"IOC large tls connection"; luajit:hello-bytes.lua; classtype:dynamic; sid:4000001; rev:1;)
```

Note that the rule also uses a custom classification that is missing from vanilla meerkat. You can omit the keyword or add the following line to `classification.config`. See [classtype](https://suricata.readthedocs.io/en/latest/rules/meta.html#classtype) keyword for more.

```
config classification: dynamic,Dynamic Lua rule triggered,1
```

`hello-bytes.lua` should exist relative to your configured rule directory. A rule script needs two hook functions called `init` and `match` to be registered in Suricata. Former is used to register needed suricata functions while the latter should return 0 or 1 depending on if there was a match. Following example rule should alert when amount of TLS connection bytes exceeds a threshold.

```
function init (args)
  local needs = {}
  --needs["type"] = "flow"
  return needs
end

function match(args)
  tscnt, tsbytes, tccnt, tcbytes = SCFlowStats()
	if tcbytes > 100000 then
		return 1
	end
  return 0
end
```

Then run the meercat and observe the stdout. Script errors are usually displayed there.

```
suricata -c $CONF/suricata.yaml -r $PCAP_FILE -vvv -S $RULES_FILE
```

You should be able to observe new alerts in fast.log and eve.json.

#### Task

 * Enable JA3 hashing in suricata;
    * `cat eve.json | jq .tls.ja3.hash | sort | uniq -c | sort -h`
 * Write a simple lua rule that implements a JA3 signature blacklist;
    * Modify that rule to function as a whilelist, i.e. you should get an alert when unapproved TLS client communicates on the network;
 * Write a rule that detects a self-signed certificate;
    * https://badssl.com/dashboard/
 * Write a simple that checks when an observed TLS certificate was generated;
    * Alert when certificate is very recent, e.g. newer than 3 hours;
    * Add the calculated age of certificate to alert as flow variable;

##### Testing TLS task with docker

Generate a self-signed certificate.

```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout keys/nginx.key -out keys/nginx.crt
```

Create `nginx.conf` file.

```
server {
        listen 80 default_server;
        listen [::]:80 default_server ipv6only=on;

        listen 443 ssl;

        root /usr/share/nginx/html;
        index index.html index.htm;

        server_name your_domain.com;
        ssl_certificate /etc/nginx/ssl/nginx.crt;
        ssl_certificate_key /etc/nginx/ssl/nginx.key;

        location / {
                try_files $uri $uri/ =404;
        }
}
```

Spin up a web server container with new key/cert and config mounted as volumes.

```
docker run -ti --rm --name some-nginx -p 80:80 -p 443:443 -v $PWD/keys/nginx.key:/etc/nginx/ssl/nginx.key -v $PWD/keys/nginx.crt:/etc/nginx/ssl/nginx.crt -v $PWD/nginx.conf:/etc/nginx/conf.d/default.conf:ro -v $PWD/web:/usr/share/nginx/html:ro nginx
```

Visit your web site in browser or use `curl`.

```
curl -k -s https://localhost
```

### Output

* https://suricata.readthedocs.io/en/latest/output/lua-output.html

Rule scripts are invoked whenever preceeding conditions match. Keeping state, invoking socketed IO, etc. can therefore be really expensive and a bad idea. On the other hand, output scripts are started with Suricata main process and run independantly until it is stopped.Consider the following `new-observed-tls.lua`. It initializes a new global hashmap on suricata process start and checks existence of observed TLS fingerprints from that map. If fingerprint is missing, it will log certificate info as newly observed and will add the fingerprint into the map as seen.

```
function init (args)
    local needs = {}
    needs["protocol"] = "tls"
    return needs
end
function setup (args)
    name = "tls.log"
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    seen = {}
end
function log(args)
    version, subject, issuer, fingerprint = TlsGetCertInfo()
    serial = TlsGetCertSerial()

    if version == nil then
        version = "<nil>"
    end
    if subject == nil then
        subject = "<nil>"
    end
    if issuer == nil then
        issuer = "<nil>"
    end
    if fingerprint == nil then
        fingerprint = "<nil>"
    end

    if fingerprint ~= nil then
        if seen[fingerprint] == nil then
            file:write(version .. "|" .. subject .. "|" .. issuer .. "|" .. fingerprint .. "|" .. serial .. "\n");
            file:flush();
            seen[fingerprint] = true
        end
    end
end
function deinit (args)
    file:close(file)
end
```

Output scripts should be explicitly configured in `suricata.yaml`

```
outputs:
  - lua:
      enabled: yes
      scripts-dir: /vagrant/lua
      scripts:
        - new-observed-tls.lua
```

Then run the meerkat. Script errors should display in the stdout.

```
suricata --af-packet -vvv -l logs/
```

Run `curl` commands against TLS sites.

```
curl https://www.facebook.com
curl https://www.microsoft.com
curl https://www.ccdcoe.org
curl https://www.github.com
```

Tail the `tls.log` file in suricata log directory. You should observe new record only on first access. But note that state is kept purely in process memory and therefore resets when suricata is stopped.

#### Tasks

 * Adapt the [suricata stats lua script from Victor Julien](https://github.com/inliniac/surilua/blob/master/stats.lua);
 * Enhance the example script;
    * Record is missing timestamp, add it;
    * Set up persistence for observed fingerprints by storing observations in Redis, as opposed to process memory;
