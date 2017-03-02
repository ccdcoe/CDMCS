# Rsyslog

 * http://www.rsyslog.com/ubuntu-repository/
 * http://www.rsyslog.com/tag/mmjsonparse/
 * http://www.rsyslog.com/doc/mmjsonparse.html
 * http://www.rsyslog.com/doc/v8-stable/configuration/modules/omelasticsearch.html

```
apt-cache policy rsyslog
rsyslog:
  Installed: 7.4.4-1ubuntu2.6
  Candidate: 8.16.0-0adiscon1trusty1
  Version table:
     8.16.0-0adiscon1trusty1 0
        500 http://ppa.launchpad.net/adiscon/v8-stable/ubuntu/ trusty/main amd64 Packages
 *** 7.4.4-1ubuntu2.6 0
        500 http://archive.ubuntu.com/ubuntu/ trusty-updates/main amd64 Packages
        100 /var/lib/dpkg/status
```

# Installing missing modules

```
sudo apt-get install rsyslog-mmjsonparse rsyslog-elasticsearch -y
```

```
sudo service rsyslog restart
```

# Verify daemon

```
grep rsyslogd /var/log/syslog
```

----
Next -> [Rsyslog filtering](rsyslog2ela.md)
