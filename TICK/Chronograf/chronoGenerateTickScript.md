# Chronograf: create kapacitor tick script

![](chronokapa.png)


```
root@TICKAlerta:~# kapacitor show chronograf-v1-903cb640-9539-469f-bd19-80f02f791cbd
ID: chronograf-v1-903cb640-9539-469f-bd19-80f02f791cbd
Error:
Template:
Type: stream
Status: enabled
Executing: true
Created: 28 Jan 17 22:49 UTC
Modified: 28 Jan 17 22:49 UTC
LastEnabled: 28 Jan 17 22:49 UTC
Databases Retention Policies: ["telegraf"."autogen"]
TICKscript:
var db = 'telegraf'

var rp = 'autogen'

var measurement = 'system'

var groupBy = ['host']

var whereFilter = lambda: TRUE

var period = 5m

var name = 'Untitled Rule'

var idVar = name + ':{{.Group}}'

var message = ''

var idTag = 'alertID'

var levelTag = 'level'

var messageField = 'message'

var durationField = 'duration'

var outputDB = 'chronograf'

var outputRP = 'autogen'

var outputMeasurement = 'alerts'

var triggerType = 'deadman'

var threshold = 0.0

var data = stream
    |from()
        .database(db)
        .retentionPolicy(rp)
        .measurement(measurement)
        .groupBy(groupBy)
        .where(whereFilter)

var trigger = data
    |deadman(threshold, period)
        .stateChangesOnly()
        .message(message)
        .id(idVar)
        .idTag(idTag)
        .levelTag(levelTag)
        .messageField(messageField)
        .durationField(durationField)

trigger
    |eval(lambda: "emitted")
        .as('value')
        .keep('value', messageField, durationField)
    |influxDBOut()
        .create()
        .database(outputDB)
        .retentionPolicy(outputRP)
        .measurement(outputMeasurement)
        .tag('alertName', name)
        .tag('triggerType', triggerType)

trigger
    |httpOut('output')

```
