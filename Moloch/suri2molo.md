# Suricata -> Alert -> ? -> Moloch

## Moloch can "take" from

* WISE
* or ADD TAG  


* WISE :: https://github.com/ccdcoe/CDMCS/blob/master/Moloch/vagrant/singlehost/source.suricata.js
* TAG :: https://gist.github.com/hillar/409a18e1604c70bb3804


* WISE <-
  * ELASTIC https://github.com/aol/moloch/blob/master/capture/plugins/wiseService/source.elasticesearch.js
   * RSyslog
   * https://gist.github.com/hillar/aeae0b6d12de4ccd8ced#file-suricata_flow2ela-lua
   * ...
  * REDIS https://github.com/aol/moloch/blob/master/capture/plugins/wiseService/source.redis.js

## suricata can output to

* file (json)
* syslog
* redis
* LUA
* ...

https://github.com/inliniac/suricata/blob/master/suricata.yaml.in#L148
https://redmine.openinfosecfoundation.org/issues/1582
https://github.com/inliniac/suricata/blob/master/src/alert-syslog.c
