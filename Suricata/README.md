
This material has been designed to be taught in a [classroom](https://ccdcoe.org/training/cyber-defence-monitoring-course-suite-module-1-feb-2019/) environment... hands-on 90% talk 10% **slides 0%**

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Suricata. We believe these classes are perfect for anyone who wants a jump start in learning Suricata or who wants a more thorough understanding of it internals.

### Suricata is intrusion detection and prevention system

> Suricata is a free and open source, mature, fast and robust network threat detection engine. The Suricata engine is capable of real time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM) and offline pcap processing.

## Day 0 :: Intro:: Feb 11 2019, starts at 13:00

 * 13:00 - 14:45
   * [Intro](/common/day_intro.md)
   * [what is Suricata](/Suricata/suricata/README.md)
   * [vagrant](/common/vagrant/), [docker](/common/docker)
   * [singlehost](/Suricata/vagrant/singlehost/)
 * 15:00 - 16:45
   * [intro to rules](/Suricata/rules/)

## Day 1 :: Single box, setting up :: Feb 12 2019

 * 09:00 - 12:30
   * [rules, cont.](/Suricata/rules)
   * [build from source](/Suricata/setup/#Build)
   * [config](/Suricata/setup/#Config)
 * 13:30 - 16:45
   * [elasticsearch, intro](/Suricata/indexing#getting-started-with-elastic)
   * [indexing alert log](/Suricata/indexing#playing-with-python)
   * [evebox](/Suricata/indexing#evebox), [scirius](/Suricata/indexing#scirius), [kibana](/Suricata/indexing#kibana)

## Day 2 :: Group up, scale out :: Feb 13 2019

 * 09:00 - 12:30
   * [dashboarding, cont.](/Suricata/indexing)
   * [elastic clustering](/Suricata/advanced-indexing#clustered-elasticsearch)
   * [redis](/Suricata/advanced-indexing#redis),[redis api](/Suricata/advanced-indexing/001-redis.ipynb),[data pipelining](/Suricata/advanced-indexing/000-pipelines.ipynb)

 * 13:30 - 16:45
   * [group work on alert handling](/Suricata/advanced-indexing#alerta)

## Day 3 :: Advanced stuff, hipster tech :: Feb 14 2019

 * 09:00 - 12:30
   * [ebpf and xdp]()

 * 13:30 - 16:45
   * [LUA scripting](/Suricata/lua)

## Day +1 :: Encore :: Feb 15 2019, ends at 12:00

 * 09:00 - 10:30
   * ...
 * 11:00 - 12:00
   * [feedback, contact exchange, thanks, etc.](/common/Closing.md)

### Homeless topics
 * [IPS]()
 * [Alerta]()
 * [septun/RSS]()
 * [pcap via unix socket]()
 * [suricata stats to TICK]()

----

Before You Come To Class please browse trough ..

 * [prereqs](https://github.com/ccdcoe/CDMCS/tree/master/prerequisites)
 * [singlehost](https://github.com/ccdcoe/CDMCS/tree/master/Suricata/vagrant/singlehost)
 * [suricata](https://suricata.readthedocs.io/en/latest/)
 * [vagrant](https://github.com/ccdcoe/CDMCS/tree/master/common/vagrant)
 * []
