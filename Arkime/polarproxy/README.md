# Polarproxy

* https://www.netresec.com/?page=Blog&month=2020-12&post=Capturing-Decrypted-TLS-Traffic-with-Arkime

```
[Unit]
Description=PolarProxy TLS pcap logger
After=network.target

[Service]
SyslogIdentifier=PolarProxy
Type=simple
User=proxyuser
WorkingDirectory=/home/proxyuser/PolarProxy
ExecStart=/home/proxyuser/PolarProxy/PolarProxy -v -p 10443,80,443 -x /var/log/PolarProxy/polarproxy.cer -f /var/log/PolarProxy/proxyflows.log -o /var/log/PolarProxy/ --certhttp 10080 --socks 1080 --httpconnect 8080 --allownontls --insecure --pcapoveripconnect 127.0.0.1:57012
KillSignal=SIGINT
FinalKillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
```
