# Grok

* https://grokdebug.herokuapp.com/
* https://github.com/logstash-plugins/logstash-patterns-core/blob/master/patterns/grok-patterns
* https://github.com/influxdata/telegraf/blob/master/plugins/inputs/logparser/grok/patterns/influx-patterns

## On regex

* http://www.ex-parrot.com/~pdw/Mail-RFC822-Address.html

## Telegraf log input

```
[[inputs.logparser]]
  files = ["/var/log/syslog"]
  from_beginning = false

  [inputs.logparser.grok]
    patterns = ["%{SYSLOGBASE} %{GREEDYDATA:string}"]
    ## Name of the outputted measurement name.
    measurement = "syslog"
    ## Full path(s) to custom pattern files.
    custom_pattern_files = []
    ## Custom patterns can also be defined here. Put one pattern per line.
    custom_patterns = '''
    '''
```

```
SELECT count(pid) FROM syslog GROUP BY host
```

* Verify that Telegraf has permissions to read the log file.

## Collecting influxdb http logs

### Rsyslog
```
vim /etc/rsyslog.d/51-influx-http.conf
```

```
if $syslogtag startswith 'influxd' and $msg startswith ' [httpd]' then {
  action(
    type="omfile"
    dirCreateMode="0700"
    FileCreateMode="0644"
    File="/var/log/influx-http.log"
  )
}
```

```
$template PerSeverity,"/var/log/severity/%syslogseverity-text%.log"

*.*    ?PerSeverity
```

### Telegraf
```
[[inputs.logparser]]
  files = ["/var/log/influx-http.log"]
  from_beginning = false

  [inputs.logparser.grok]
    patterns = ["%{SYSLOGBASE} \S+ %{COMMONAPACHELOG}"]
    ## Name of the outputted measurement name.
    measurement = "syslog_influx_http"
    ## Full path(s) to custom pattern files.
    custom_pattern_files = ["/opt/patterns.txt"]
    ## Custom patterns can also be defined here. Put one pattern per line.
    custom_patterns = '''
    '''
```

```
VHOSTCOMMONAPACHELOG %{IPORHOST:http_vhost}:?%{IPORHOST:http_port}? %{IPORHOST:http_clientip} %{USER:http_ident} %{USER:http_auth} \[%{HTTPDATE:http_timestamp}\] "(?:%{WORD:http_method} %{NOTSPACE:http_request}(?: HTTP/%{NUMBER:http_version})?|%{DATA:http_rawrequest})" %{NUMBER:http_response} (?:%{NUMBER:http_bytes}|-) "%{DATA:http_referer}" "%{DATA:http_useragent}"
COMMONAPACHELOG %{IPORHOST:http_clientip:tag} %{USER:http_ident} %{USER:http_auth} \[%{HTTPDATE:http_timestamp:ts-httpd}\] "(?:%{WORD:http_method:tag} %{NOTSPACE:http_request:tag}(?: HTTP/%{NUMBER:http_version})?|%{DATA:http_rawrequest:string})" %{NUMBER:http_response:tag} (?:%{NUMBER:http_bytes:int}|-) "%{DATA:http_referer:string}" "%{DATA:http_useragent:string}"
```
