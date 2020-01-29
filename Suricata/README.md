
This material has been designed to be taught in a [classroom](https://ccdcoe.org/training/cyber-defence-monitoring-course-module-1/) environment... hands-on 80% + talk 40% + **slides 0%** = 120% hard work 

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Suricata. We believe these classes are perfect for anyone who wants a jump start in learning Suricata or who wants a more thorough understanding of it internals.

### Suricata is intrusion detection and prevention system

> Suricata is a free and open source, mature, fast and robust network threat detection engine. The Suricata engine is capable of real time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM) and offline pcap processing.

# Suricata in-house course (CDMCS M1) - February 10-14, 2020

Provided timeline is preliminary and will develop according to the actual progress of the class.

## Day 0 :: Intro:: Feb 10 2020, *starts at 13:00!*

 * 13:00 - 14:45
   * [Intro](/common/day_intro.md)
   * [what is Suricata](/Suricata/suricata/README.md)
   * [vagrant](/common/vagrant/), [docker](/common/docker)
   * [singlehost](/singlehost)
 * 15:00 - 16:45
   * [intro to rules](/Suricata/rules/)

## Day 1 :: Single box, setting up :: Feb 11 2020

 * 09:00 - 12:30
   * [build from source](/Suricata/setup/#Build)
 * 13:30 - 16:45
   * [config](/Suricata/setup/#Config)
   * [rules, cont.](/Suricata/rules)

## Day 2 :: Group up, scale out :: Feb 12 2020

 * 09:00 - 12:30
   * [elasticsearch, intro](/Suricata/indexing#getting-started-with-elastic)
   * [indexing alert log](/Suricata/indexing#playing-with-python)

 * 13:30 - 16:45
   * [elastic clustering](/Suricata/advanced-indexing#clustered-elasticsearch)
   * [redis](/Suricata/advanced-indexing#redis),[redis api](/Suricata/advanced-indexing/001-redis.ipynb),[data pipelining](/Suricata/advanced-indexing/000-pipelines.ipynb)
   * [evebox](/Suricata/indexing#evebox), [scirius](/Suricata/indexing#scirius), [kibana](/Suricata/indexing#kibana)

## Day 3 :: Advanced stuff, hipster tech :: Feb 13 2020

 * 09:00 - 12:30
   * [ebpf and xdp](https://suricata.readthedocs.io/en/latest/capture-hardware/ebpf-xdp.html)

 * 13:30 - 16:45
   * [LUA scripting](/Suricata/lua)

## Day +1 :: Last but not least :: Feb 14 2020, *ends at 12:00*

 * 09:00 - 11:00
   * [load pcap via unix socket](/Suricata/unix-socket)
   * [evebox](/Suricata/indexing#evebox), [scirius](/Suricata/indexing#scirius), [kibana](/Suricata/indexing#kibana)
 * 11:00 - 12:00
   * [feedback, contact exchange, thanks, etc.](/common/Closing.md)

### Homeless topics
 * [IPS]()
 * [Alerta]()
 * [septun/RSS]()
 * [suricata stats to TICK]()


### Before You Come To Class please browse trough ..

 * [prereqs](https://github.com/ccdcoe/CDMCS/tree/master/prerequisites)
 * [singlehost](https://github.com/ccdcoe/CDMCS/tree/master/Suricata/vagrant/singlehost)
 * [suricata](https://suricata.readthedocs.io/en/latest/)
 * [vagrant](https://github.com/ccdcoe/CDMCS/tree/master/common/vagrant)


----

# Suricata mobile course - March 02-06, 2020

Provided timeline is preliminary and will develop according to the actual progress of the class.

## Day 0 :: Intro:: Mar 02 2020, *starts at 11:00*

 * 11:00 - 12:30
   * [Intro](/common/day_intro.md)
   * [what is Suricata](/Suricata/suricata/README.md)
   * [vagrant](/common/vagrant/), [docker](/common/docker)
   * [singlehost](/Suricata/vagrant/singlehost/)
 * 14:00 - 15:45
   * [intro to rules](/Suricata/rules/)

## Day 1 :: Single box, setting up :: Feb 11 2020

 * 08:00 - 12:00
   * [build from source](/Suricata/setup/#Build)
 * 13:30 - 15:45
   * [config](/Suricata/setup/#Config)
   * [rules, cont.](/Suricata/rules)

## Day 2 :: Group up, scale out :: Feb 12 2020

 * 08:00 - 12:00
   * [elasticsearch, intro](/Suricata/indexing#getting-started-with-elastic)
   * [indexing alert log](/Suricata/indexing#playing-with-python)

 * 13:30 - 15:45
   * [elastic clustering](/Suricata/advanced-indexing#clustered-elasticsearch)
   * [redis](/Suricata/advanced-indexing#redis),[redis api](/Suricata/advanced-indexing/001-redis.ipynb),[data pipelining](/Suricata/advanced-indexing/000-pipelines.ipynb)
   * [evebox](/Suricata/indexing#evebox), [scirius](/Suricata/indexing#scirius), [kibana](/Suricata/indexing#kibana)

## Day 3 :: Advanced stuff, hipster tech :: Feb 13 2020

 * 08:00 - 12:00
   * [ebpf and xdp](https://suricata.readthedocs.io/en/latest/capture-hardware/ebpf-xdp.html)

 * 13:30 - 15:45
   * [LUA scripting](/Suricata/lua)

## Day +1 :: Last but not least :: Feb 14 2020, *ends at 12:00*

 * 08:00 - 11:00
   * [load pcap via unix socket](/Suricata/unix-socket)
   * [evebox](/Suricata/indexing#evebox), [scirius](/Suricata/indexing#scirius), [kibana](/Suricata/indexing#kibana)
 * 11:00 - 12:00
   * [feedback, contact exchange, thanks, etc.](/common/Closing.md)

### Homeless topics
 * [IPS]()
 * [Alerta]()
 * [septun/RSS]()
 * [suricata stats to TICK]()


### Before You Come To Class please browse trough ..

 * [prereqs](https://github.com/ccdcoe/CDMCS/tree/master/prerequisites)
 * [singlehost](https://github.com/ccdcoe/CDMCS/tree/master/Suricata/vagrant/singlehost)
 * [suricata](https://suricata.readthedocs.io/en/latest/)
 * [vagrant](https://github.com/ccdcoe/CDMCS/tree/master/common/vagrant)

