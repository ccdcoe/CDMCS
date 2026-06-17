# PolarProxy

[PolarProxy](https://www.netresec.com/?page=PolarProxy) is a transparent TLS-inspection (MITM) proxy from Netresec. It terminates an incoming TLS connection, decrypts it, re-encrypts to the real destination, and writes the **decrypted** traffic out as PCAP. We feed that decrypted PCAP into a dedicated Arkime *node* over PCAP-over-IP, so otherwise-opaque TLS sessions become fully searchable in Arkime — payload and all.

```
client ──TLS──▶ PolarProxy ──TLS──▶ real server
                    │ decrypted PCAP (PCAP-over-IP)
                    ▼
               Arkime  "polar" node ──▶ Elasticsearch / Viewer :8006
```

* https://www.netresec.com/?page=PolarProxy
* https://www.netresec.com/?page=Blog&month=2020-12&post=Capturing-Decrypted-TLS-Traffic-with-Arkime
* https://arkime.com/settings#reader-poi

## Setting up PolarProxy

Download PolarProxy into `/opt/PolarProxy`. Since v2 it ships as a **self-contained binary** (~75 MB — the .NET runtime is bundled, so there is nothing else to install). The tarball also contains a sample systemd unit and example rulesets. At the time of writing the current release is PolarProxy 2.0.1.

```
mkdir /opt/PolarProxy
cd /opt/PolarProxy
wget -O polarproxy.tar.gz 'https://www.netresec.com/?download=PolarProxy'
tar -zxvf polarproxy.tar.gz
chmod +x PolarProxy
```

### Systemd service

PolarProxy ships a sample `PolarProxy.service`; we adjust the paths and flags. Create `/etc/systemd/system/PolarProxy.service`:

```
[Unit]
Description=PolarProxy TLS pcap logger
After=network.target

[Service]
SyslogIdentifier=PolarProxy
Type=simple
WorkingDirectory=/opt/PolarProxy
ExecStart=/opt/PolarProxy/PolarProxy -v -p 10443,80,443 -x /var/log/PolarProxy/polarproxy.cer -f /var/log/PolarProxy/proxyflows.log -o /var/log/PolarProxy/ --certhttp 10080 --socks 1080 --httpconnect 8080 --nontls allow --leafcert sign --pcapoveripconnect 127.0.0.1:57012
KillSignal=SIGINT
FinalKillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
```

That command line is dense — run `/opt/PolarProxy/PolarProxy --help` for the full list, but here is what each flag does:

| Flag | Meaning |
|------|---------|
| `-p 10443,80,443` | transparent proxy — `LISTEN-PORT,DECRYPTED-PORT,TARGET-PORT`: **listen** for TLS on 10443, label the **decrypted** stream as port **80** in the PCAP, connect to the real **target** on 443 |
| `-x …/polarproxy.cer` | export PolarProxy's public root CA (DER) so clients can import and trust it |
| `-f …/proxyflows.log` | per-flow metadata log: timestamp, internal/external 5-tuples, SNI, cert hash, **JA3 + JA4** |
| `-o /var/log/PolarProxy/` | output directory for hourly-rotated decrypted PCAP files |
| `--certhttp 10080` | small HTTP server that serves the CA cert for download |
| `--socks 1080` / `--httpconnect 8080` | SOCKS and HTTP-CONNECT proxy entry points clients can point at |
| `--nontls allow` | let non-TLS connections pass straight through |
| `--leafcert sign` | mint per-site leaf certs on the fly, signed by PolarProxy's CA |
| `--pcapoveripconnect 127.0.0.1:57012` | stream the decrypted PCAP to a PCAP-over-IP **listener** (our Arkime polar node) |

The service writes its cert, flow log and PCAPs into `/var/log/PolarProxy`. Create that directory **before** starting the service, or it will fail:

```
mkdir /var/log/PolarProxy
```

## Configuring Arkime to accept PCAP over IP

PolarProxy connects out with `--pcapoveripconnect`, so Arkime has to be the PCAP-over-IP **server** (the listener). A capture that reads PCAP-over-IP no longer sniffs interfaces, so we run it as a **separate Arkime node** next to the live-capture node.

Add a `[polar]` node section at the **end** of `config.ini`. (The capture guide warns against adding options at the end of the file — that is exactly because end-of-file starts a *node* section, which is what we want here.) Put the node overrides under it:

```
[polar]
pcapReadMethod=pcap-over-ip-server
viewPort=8006
simpleCompression=none
```

* `pcapReadMethod=pcap-over-ip-server` — Arkime listens for PCAP-over-IP on the default port **57012**, which matches PolarProxy's `--pcapoveripconnect 127.0.0.1:57012`.
* `viewPort=8006` — the polar viewer needs its own port so it doesn't collide with the main viewer on 8005.
* `simpleCompression=none` — proxy volume is low, and Arkime can't rebuild sessions from a gzip PCAP that is still being written.

Each capture node needs a matching viewer node. Clone the live-capture units:

```
cp /etc/systemd/system/arkime-capture.service /etc/systemd/system/arkime-polar.service
cp /etc/systemd/system/arkime-viewer.service /etc/systemd/system/arkime-viewer-polar.service
```

In `arkime-polar.service`, **comment out (or remove) the `ExecStartPre`** interface-config line — there is no interface to set up here — and add `--node polar`:

```
ExecStart=/opt/arkime/bin/capture -c /opt/arkime/etc/config.ini --node polar
```

Do the same `--node polar` change in `arkime-viewer-polar.service`:

```
ExecStart=/opt/arkime/bin/node viewer.js -c /opt/arkime/etc/config.ini --node polar
```

## Starting it up

Order matters: bring up the Arkime polar node (the PCAP-over-IP **listener**) first, then PolarProxy (the **client** that connects to it).

```
systemctl daemon-reload
systemctl enable --now arkime-polar.service
systemctl enable --now arkime-viewer-polar.service
systemctl enable --now PolarProxy.service
```

Confirm they are healthy and the two key ports are open:

```
systemctl is-active arkime-polar arkime-viewer-polar PolarProxy
ss -ltnp | grep -E ':10443|:57012'   # PolarProxy on 10443, Arkime PCAP-over-IP on 57012
```

## Testing

Send a request through the proxy. `--connect-to` tells curl to open the connection to PolarProxy's `10443` while still requesting (and sending the SNI for) `www.netresec.com`; PolarProxy uses that SNI to reach the real server.

```
curl --connect-to www.netresec.com:443:127.0.0.1:10443 https://www.netresec.com/
```

The leaf cert PolarProxy mints isn't trusted yet, so add `--insecure` to ignore cert errors for now (or trust the CA — see below).

```
curl --insecure --connect-to www.netresec.com:443:127.0.0.1:10443 https://www.netresec.com/
```

Then find the decrypted session in Arkime — **in the polar viewer on port 8006, not the main viewer**:

```
http://<host>:8006/
```

**Gotcha — give it a moment.** PolarProxy only writes a flow once the session closes (or hits its idle timeout), and Arkime then has to index it, so a single short request can take ~30–60 s to appear. While you wait, confirm PolarProxy actually decrypted it — every line in the flow log ends with the client's JA3 and JA4 fingerprints:

```
tail -f /var/log/PolarProxy/proxyflows.log
```

## Adding a trusted certificate

PolarProxy generates its own root CA on first run and exports it (per the `-x` flag) to `/var/log/PolarProxy/polarproxy.cer`. Import that CA so clients trust the leaf certs PolarProxy mints, and the warnings go away.

### Linux

Convert the DER cert and register it (choose `extra/PolarProxy-root-CA.crt` when prompted):

```
sudo mkdir /usr/share/ca-certificates/extra
sudo openssl x509 -inform DER -in /var/log/PolarProxy/polarproxy.cer -out /usr/share/ca-certificates/extra/PolarProxy-root-CA.crt
sudo dpkg-reconfigure ca-certificates
```

The curl test now works without `--insecure`:

```
curl --connect-to www.netresec.com:443:127.0.0.1:10443 https://www.netresec.com/
```

In practice you wouldn't juggle `--connect-to`; instead route clients' outbound 443 through PolarProxy — transparently, or via the `--socks 1080` / `--httpconnect 8080` entry points.

### Windows

* https://docs.microsoft.com/en-us/skype-sdk/sdn/articles/installing-the-trusted-root-certificate

```
MMC -> Add / remove snap-in -> certificates -> local computer -> Import
```
