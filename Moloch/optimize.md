# optimization

```
#!/bin/bash

DIR=/opt/moloch/logs/
cd $DIR
ulimit -n 240000

#systemctl restart molochwise.systemd.service
#pgrep node | while read line; do taskset -pc 1-15 $line ; done

sleep 2

nohup /opt/moloch/bin/moloch-capture -c /opt/moloch/etc/config.ini &

sleep 3

taskset -pc 16  `pstree -Aap | pcregrep -o2 '(moloch-pcap\d+)},(\d+)' | sort -n`
taskset -pc 16  `pstree -Aap | pcregrep -o2 '(moloch-simple)},(\d+)' | sort -n`
taskset -pc 16  `pgrep moloch-capture`

num=18

for pid in `pstree -Aap | pcregrep -o2 '(moloch-pkt\d+)},(\d+)' | sort -n`; do
  taskset -pc $num $pid && num=$((num+1))
done
```
