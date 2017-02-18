# Common Event Expression

 * https://cee.mitre.org/
 * http://www.rsyslog.com/tag/cee-enhanced/

## Log format

```
Feb 25 11:23:42 suricata suricata[26526]: @cee: {"timestamp":"2015-12-07T19:30:54.863188+0000","flow_id":139635731853600,"pcap_cnt":142,"event_type":"alert","src_ip":"192.168.11.11","src_port":59523,"dest_ip":"192.168.12.12","dest_port":443,"proto":"TCP","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":2013926,"rev":8,"signature":"ET POLICY HTTP traffic on port 443 (POST)","category":"Potentially Bad Traffic","severity":2}}
```

## Suricata configuration

```
grep cee -B2 -A3 /etc/suricata/suricata.yaml
```
