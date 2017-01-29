# Send alerts to Alerta

## Send some test alerts

see http://alerta.readthedocs.io/en/latest/cli.html

```
$ alerta send -r web01 -e NodeDown -E Production -S Website -s major -t "Web server is down." -v ERROR

```

```
$ alerta send -r user01 -e loginError -s major -E Production -S Security \
-t 'user01 login failed.'
57eb528a-84bf-4080-b54a-37e2888207f3 (indeterminate -> major)

$ alerta send -r user01 -e loginError -s major -E Production -S Security \
-t 'user01 login failed.'
57eb528a-84bf-4080-b54a-37e2888207f3 (1 duplicates)

```

## Real alerts

see
* http://alerta.readthedocs.io/en/latest/server.html#server-api
* https://docs.influxdata.com/kapacitor/v1.2/nodes/alert_node/#alerta

```

cat >> /etc/kapacitor/kapacitor.conf <<EOF
[alerta]
  enabled = true
  url = "http://192.168.11.11"
  token = "Test-Token"
  environment = "Production"
  origin = "kapacitor"
EOF

```

## Basics

### State-based
Alerta is called state-based because it will automatically change the alert status based on the current and previous severity of alerts and subsequent user actions.

### Alert timeout

Alert timeout values can be used to automatically “expire” alerts that are no longer active. The default timeout period for an alert is 86400 seconds, or one day.

Timeouts can be used for any type of alert but are most useful for alerts which do not have a corresponding “clear” or “ok” state, such as syslog messages. Timeouts are set on a per-alert basis.

### De-Duplication

When an alert with the same environment-resource-event combination is received with the same severity, the alert is de-duplicated.
This means that information from the de-duplicated alert is used to update key attributes of the existing alert (like duplicateCount, repeat flag, value, text and lastReceiveTime) and the new alert is not shown.

### Correlation

There are two ways alerts can be correlated:
* When an alert with the same environment-resource-event combination is received with a different severity, then the alert is correlated.
* When a alert with the same environment-resource combination is received with an event in the correlate list of related events with any severity, then the alert is correlated.

In both cases, this means that information from the correlated alert is used to update key attributes of the existing alert (like severity, event, value, text and lastReceiveTime) and the new alert is not shown.

### History

Whenever an alert status or severity changes, that change is recorded in the alert history log. This is to allow operations staff follow the lifecycle of a particular alert, if necessary.

-------
-> Next [External Notification](notify.md)
