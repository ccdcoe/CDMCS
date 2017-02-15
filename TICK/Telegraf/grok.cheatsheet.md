
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
SELECT count("program")/count(distinct("program"))  FROM "telegraf"."autogen"."snoopy" WHERE time > now() - 1h GROUP BY time(10m)
```
