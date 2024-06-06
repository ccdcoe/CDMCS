# Polarproxy

* https://www.netresec.com/?page=PolarProxy
* https://www.netresec.com/?page=Blog&month=2020-12&post=Capturing-Decrypted-TLS-Traffic-with-Arkime

## Setting up Polarproxy

Get polarproxy and set it up in /opt/PolarProxy dir

```
mkdir /opt/PolarProxy
cd /opt/PolarProxy
wget -O polarproxy.tar.gz 'https://www.netresec.com/?download=PolarProxy'
tar -zxvf polarproxy.tar.gz
```

### Systemd service

PolarProxy comes with a sample Systemd service file in `PolarProxy.service` file. We slightly edit it to make use of different directory paths and user accounts. Copy or create the `/etc/systemd/system/PolarProxy.service` file.

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

## Configuring Arkime to accept PCAP over IP

If we set Arkime to capture PCAP over IP connections, it will no longer listen on the network interfaces. For that, it would make sense to spin up another Arkime instance.

A native way to do this is by adding another arkime Node. Add this section at the end of your `config.ini`.

```
[polar]
```

Change the `pcapReadMethod` in the polar section of the config file. We can override some other values as well. Arkime capture node needs a corresponding viewer node. Since they might be on the same host as live capture, then their ports might collide. Finally, PCAP compression might also get in the way, as proxy traffic volume is quite low and arkime cannot rebuild sessions from PCAP files that are being actively written to.

```
pcapReadMethod=pcap-over-ip-server
viewPort=8006
simpleCompression=none
```

Let's create a new arkime service for PolarProxy capture. We also need a corresponding viewer when using node configuration.

```
cp /etc/systemd/system/arkimecapture.service /etc/systemd/system/arkimepolar.service
cp /etc/systemd/system/arkimeviewer.service /etc/systemd/system/arkimeviewerpolar.service
```

Comment the `ExecStartPre`, since we don't need to configure any actual interfaces. Modify the `ExecStart` to reflect the new paths and also create a separate log file to distinguish separate processes.

```
...
ExecStart=/opt/arkime/bin/capture -c /opt/arkime/etc/config.ini --node polar
...
```

Make sure to also do this with viewer node in `arkimeviewerpolar.service`.

```
...
ExecStart=/opt/arkime/bin/node viewer.js -c /opt/arkime/etc/config.ini --node polar
...
```

Before starting the new systemd services, make sure that all the paths and directories actually exists on the system. For example:

```
mkdir /var/log/PolarProxy
```

Start the new services.

```
systemctl daemon-reload

systemctl enable --now arkimepolar.service

systemctl enable --now arkimeviewerpolar.service

systemctl start PolarProxy.service
```
Let's test if we can take our proxy for a spin...

```
curl --connect-to www.netresec.com:443:127.0.0.1:10443 https://www.netresec.com/
```

As expected with self-signed certs, they are not trusted. You can add the `--insecure` flag to the `curl` command above to ignore any certificate issues.

Now wait a minute or two and let's check if we can see that traffic in Arkime.


## Adding a trusted certificate

In our env, PolarProxy exports its public certificate to `/var/log/PolarProxy/polarproxy.cer`

### Linux

We can make our machine to trust it with the following. Make sure to select the `extra/PolarProxy-root-CA.crt` Certificate Authority when prompted.

```
sudo mkdir /usr/share/ca-certificates/extra
sudo openssl x509 -inform DER -in /var/log/PolarProxy/polarproxy.cer -out /usr/share/ca-certificates/extra/PolarProxy-root-CA.crt
sudo dpkg-reconfigure ca-certificates
```

Now this command should work without issues

```
curl --connect-to www.netresec.com:443:127.0.0.1:10443 https://www.netresec.com/
```

Ideally, instead of tricking around with curl, you would redirect all traffic outbound to port 443 via your PolarProxy.

### Windows

* https://docs.microsoft.com/en-us/skype-sdk/sdn/articles/installing-the-trusted-root-certificate

```
MMC -> Add / remove stap-in -> certificates -> local computer -> Import
```
