# Run 'make install-conf' if you want to install initial configuration files. 

```
root@suricata:~/oisf# make install-conf
install -d "/usr/local/etc/suricata/"
install -d "/usr/local/var/log/suricata/files"
install -d "/usr/local/var/log/suricata/certs"
install -d "/usr/local/var/run/"
install -m 770 -d "/usr/local/var/run/suricata"
```
