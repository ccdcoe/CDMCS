# logstash

 * https://www.elastic.co/guide/en/logstash/master/index.html

```
LOGSTASH="logstash-6.1.2.deb"
[[ -f $LOGSTASH ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/logstash/$LOGSTASH -O $LOGSTASH
dpkg -s logstash || dpkg -i $LOGSTASH > /dev/null 2>&1
```

```
/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/suricata.conf -t || exit 1
```
