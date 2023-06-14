# Polarproxy

* https://www.netresec.com/?page=PolarProxy
* https://www.netresec.com/?page=Blog&month=2020-12&post=Capturing-Decrypted-TLS-Traffic-with-Arkime

## Setting up Polarproxy

Get polarproxy and set it up in /opt/PolarProxy dir

```
mkdir /opt/PolarProxy
cd /opt/PolarProxy
wget -O polarproxy.tar.gz 'https://www.netresec.com/?download=PolarProxy'
tar -zxvf polarproxy.tar
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
ExecStart=/opt/PolarProxy/PolarProxy -v -p 10443,80,443 -x /var/log/PolarProxy/polarproxy.cer -f /var/log/PolarProxy/proxyflows.log -o /var/log/PolarProxy/ --certhttp 10080 --socks 1080 --httpconnect 8080 --allownontls --insecure --pcapoveripconnect 127.0.0.1:57012
KillSignal=SIGINT
FinalKillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
```

## Configuring Arkime to accept PCAP over IP

If we set Arkime to capture PCAP over IP connections, it will no longer listen on the network interfaces. For that, it would make sense to spin up another Arkime instance.

Let's make a copy of the `config.ini` file and configure another Systemd service to spin up another Arkime instance to use that config file.

```
cp /opt/arkime/etc/config.ini /opt/arkime/etc/config-polarproxy.ini
```

Change the `pcapReadMethod` in the new default section of the config file.

```
pcapReadMethod=pcap-over-ip-server
```

Let's create a new arkime service for PolarProxy capture

```
cp /etc/systemd/system/arkimecapture.service /etc/systemd/system/arkimepolar.service
```

Comment the `ExecStartPre`, since we don't need to configure any actual interfaces. Modify the `ExecStart` to reflect the new paths and also create a separate log file to distinguish separate processes.

```
...
#ExecStartPre=-/opt/arkime/bin/arkime_config_interfaces.sh -c /opt/arkime/etc/config.ini -n default
ExecStart=/bin/sh -c '/opt/arkime/bin/capture --node arkimepolar -c /opt/arkime/etc/config-polarproxy.ini ${OPTIONS} >> /opt/arkime/logs/arkimepolar.log 2>&1'
...
```

Before starting the new systemd services, make sure that all the paths and directories actually exists on the system. For example:

```
mkdir /var/log/PolarProxy
```

Start the new services.

```
systemctl daemon-reload
systemctl start arkimepolar.service
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
