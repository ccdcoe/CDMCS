# Scirius configuration


see:

* https://github.com/StamusNetworks/scirius/blob/master/scirius/settings.py
* config from deb is located under ```/etc/scirius/local_settings.py"```
* config from git is ``<where ever you cloned me>/scirius/local_settings.py```

## pointing to corrent elasticsearch index (from git)
```
SCIRIUS_PATH="/opt/scirius"
SCIRIUS_CONF=$SCIRIUS_PATH/scirius/local_settings.py

echo 'ELASTICSEARCH_LOGSTASH_INDEX = "suricata-"'  >> $SCIRIUS_CONF
echo 'ELASTICSEARCH_LOGSTASH_ALERT_INDEX = "suricata-"'  >> $SCIRIUS_CONF
echo 'ELASTICSEARCH_VERSION = 6' >> $SCIRIUS_CONF
```

 * point scirius to evebox
