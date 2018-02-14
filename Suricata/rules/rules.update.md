# updating rules

* https://github.com/OISF/suricata-update

## install tool
```
pip install suricata-update
```

## enable source and update rules
```
suricata-update list-source
suricata-update enable-source sslbl/ssl-fb-blacklist
suricata-update 
```

## point suricata.yaml to new rules file
```
rules:
  - /var/lib/suricata/rules/suricata.rules
```

## reload suricata
```
suricatasc -c "reload-rules"
kill -USR2 `pgrep Suricata`
```
