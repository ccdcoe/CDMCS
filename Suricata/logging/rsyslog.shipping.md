# create a simple rsyslog client-server setup

## client

```
echo "*.* @192.168.10.20:514"
systemctl restart rsyslogd.service
```

## server

```
cat > /etc/rsyslog.d/udp-server.conf <<EOF
module(load="imudp")
input(type="imudp" port="514")
EOF
```
```
systemctl restart rsyslogd.service
```
```
tail /var/log/syslog
```
## salt
```
vim send-logs.conf
ifconfig
vim send-logs.conf
vim /etc/rsyslog.conf
service rsyslog restart
salt-cp '*' send-logs.conf /etc/rsyslog.d/send-logs.conf
salt '*' service.restart rsyslog
salt '*' cmd.run 'logger test'
tail /var/log/syslog
```
