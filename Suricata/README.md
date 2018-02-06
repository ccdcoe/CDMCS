
This material has been designed to be taught in a [classroom](https://ccdcoe.org/cyber-defence-monitoring-course-suite-module-1-1.html) environment... hands-on 90% talk 10% **slides 0%**

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Suricata. We believe these classes are perfect for anyone who wants a jump start in learning Suricata or who wants a more thorough understanding of it internals.

### Suricata is intrusion detection and prevention system

> Suricata is a free and open source, mature, fast and robust network threat detection engine. The Suricata engine is capable of real time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM) and offline pcap processing.

## Day 0 :: Intro:: Feb 12 2018, starts at 13:00

 * 13:00 - 14:45
   * [Intro](/common/day_intro.md)
   * [what is Suricata](/Suricata/suricata/README.md)
   * [vagrant](/common/vagrant_intro.md)
   * [singlehost](/Suricata/vagrant/singlehost/)
 * 15:00 - 16:45
   * [intro to rules](/Suricata/rules/rules.intro.md)
   * [intro to dashboarding]()

## [Day 1](/Suricata/classroom/day_1/README.md) :: Single Box :: Feb 13 2018

 * 09:00 - 11:45
   * [build from source](/Suricata/setup/build.md)
   * [config](/Suricata/setup/config.md)
   * [managing rules](/Suricata/suricata/rules.md)
 * 13:00 - 16:45
   * [elasticsearch](/common/elastic), [install](/common/elastic/elastic.install.md), [mappings](/common/elastic/elastic.mappings.md)
   * [evebox](/Suricata/evebox)
   * [scirius](/Suricata/scirius)
   * [rules, cont.](/Suricata/rules)

## [Day 2](/Suricata/classroom/day_2/README.md) :: Scale up :: Feb 14 2018

* 09:00 - 11:45
  * [multihost with salt](/Suricata/vagrant/multihost)
  * [Metrix](/TICK/Telegraf/README.md)
  * [deployment]()
* 13:00 - 16:45
  * [elastic, clustered](/common/elastic/elastic.cluster.md)
  * [indexing alert log](/Suricata/logging/)
  * [Kibana](/common/kibana.md)


## [Day 3](/Suricata/classroom/day_3/README.md) :: Usage :: Feb 15 2018

* 09:00 - 11:45
  * [Suricata LUA output](/Suricata/suricata/stats2influxdb.md)
  * [Suricata LUA rules](/Suricata/suricata/rules.lua.md)
  * [IPS]()
* 13:00 - 16:45
  * [Suricata unix socket](/Suricata/suricata/unixsocket.md)
  * [Suricata loading pcaps](/Suricata/suricata/LoadPcaps.md)


## Day +1 :: :: Feb 16 2018, ends at 12:00

* 09:00 - 09:45
  * [Making sense out of Alerts](/common/kibana.md)
  * []()
  * [feedback, contact exchange, thanks, etc.](/common/Closing.md)


----

Before You Come To Class please browse trough ..

* [Suricata](/Suricata/suricata/README.md)
* [Scirius](/Suricata/scirius/README.md)
* [Evebox](/Suricata/evebox/README.md)
