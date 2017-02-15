
### syslog

```
Feb 15 15:17:01 vspeherestudent-14-master148716303459424800 CRON[4174]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Feb 15 16:17:01 vspeherestudent-14-master148716303459424800 CRON[7065]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Feb 15 17:17:01 vspeherestudent-14-master148716303459424800 CRON[9959]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Feb 15 18:17:01 vspeherestudent-14-master148716303459424800 CRON[13168]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Feb 15 19:17:01 vspeherestudent-14-master148716303459424800 CRON[16065]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Feb 15 20:17:01 vspeherestudent-14-master148716303459424800 CRON[18969]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Feb 15 21:17:01 vspeherestudent-14-master148716303459424800 CRON[20954]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Feb 15 22:17:01 vspeherestudent-14-master148716303459424800 CRON[22246]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Feb 15 23:17:01 vspeherestudent-14-master148716303459424800 CRON[23858]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Feb 16 00:17:01 vspeherestudent-14-master148716303459424800 CRON[26454]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
```


```toml
[[inputs.logparser]]
files = ["/var/log/syslog"]
from_beginning = false 
[inputs.logparser.grok]
patterns = ["%{MINISYSLOG}"]
measurement = "syslog"
custom_patterns = '''
MINISYSLOG %{SYSLOGBASE} %{GREEDYDATA:string:drop}
'''
```

```sql
SELECT count(distinct("program")  FROM "telegraf"."autogen"."syslog" WHERE time > now() - 1h GROUP BY time(1h)
```

### snoopy

```
Feb 16 00:26:57 vspeherestudent-14-master148716303459424800 snoopy[26950]: [uid:0 sid:1947 tty: cwd:/root filename:/usr/bin/dmidecode]: dmidecode 
Feb 16 00:26:57 vspeherestudent-14-master148716303459424800 snoopy[26950]: [uid:0 sid:1947 tty: cwd:/root filename:/usr/sbin/dmidecode]: dmidecode 
Feb 16 00:26:57 vspeherestudent-14-master148716303459424800 snoopy[26951]: [uid:0 sid:1947 tty: cwd:/root filename:/usr/sbin/dmidecode]: /usr/sbin/dmidecode 
Feb 16 00:26:57 vspeherestudent-14-master148716303459424800 snoopy[26952]: [uid:0 sid:1947 tty: cwd:/root filename:/usr/local/sbin/dmesg]: dmesg 
Feb 16 00:26:57 vspeherestudent-14-master148716303459424800 snoopy[26952]: [uid:0 sid:1947 tty: cwd:/root filename:/usr/local/bin/dmesg]: dmesg 
Feb 16 00:26:57 vspeherestudent-14-master148716303459424800 snoopy[26952]: [uid:0 sid:1947 tty: cwd:/root filename:/usr/bin/dmesg]: dmesg 
Feb 16 00:26:57 vspeherestudent-14-master148716303459424800 snoopy[26952]: [uid:0 sid:1947 tty: cwd:/root filename:/usr/sbin/dmesg]: dmesg 
Feb 16 00:26:57 vspeherestudent-14-master148716303459424800 snoopy[26952]: [uid:0 sid:1947 tty: cwd:/root filename:/sbin/dmesg]: dmesg 
Feb 16 00:26:57 vspeherestudent-14-master148716303459424800 snoopy[26952]: [uid:0 sid:1947 tty: cwd:/root filename:/bin/dmesg]: dmesg 
Feb 16 00:27:40 vspeherestudent-14-master148716303459424800 snoopy[26984]: [uid:0 sid:19450 tty:/dev/pts/3 cwd:/tmp filename:/usr/bin/tail]: tail /var/log/auth.log 
```

```toml
[[inputs.logparser]]
files = ["/var/log/auth.log"]
from_beginning = false 
[inputs.logparser.grok]
patterns = ["%{AUTH_SNOOPY}"]
measurement = "snoopy"
custom_patterns = '''
AUTH_SNOOPY %{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} snoopy(?:\[%{POSINT:pid}\])?: \[uid:%{INT:uid:int} sid:%{INT:sid:int} tty:%{DATA:tty:tag} cwd:%{DATA:cwd} filename:%{DATA:filename}\]: %{GREEDYDATA:command:tag}
'''
```

```sql
SELECT count("cwd")/count(distinct("cwd"))  FROM "telegraf"."autogen"."snoopy" WHERE time > now() - 1h GROUP BY time(1m)
```
