# Suricata Unix Socket

> Restarting suricata is a no no. If you have a lot of rules, this will take a long time
> You would not want to miss anything, would you?

### Suricata can listen to a unix socket and accept commands from the user. 

see:
* https://home.regit.org/2012/09/a-new-unix-command-mode-in-suricata/
* https://github.com/inliniac/suricata/blob/89ba5816dc303d54741bdfd0a3896c7c1ce50d91/src/unix-manager.c#L922
* https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Unix_Socket#Protocol
* https://github.com/inliniac/suricata/tree/master/scripts/suricatasc
* http://suricata.readthedocs.io/en/latest/rule-management/rule-reload.html
* http://suricata.readthedocs.io/en/latest/unix-socket.html

samples : 
* https://github.com/hillar/vagrant_suricata_influxdb_grafana/blob/master/suri-influxdb.py
* https://gist.github.com/hillar/309e93d5b555095d07b9
