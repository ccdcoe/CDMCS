
This material has been designed to be taught in a [classroom](https://ccdcoe.org/cyber-defence-monitoring-course-suite-module-1-1.html) environment... hands-on 90% talk 10% **slides 0%**

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Suricata. We believe these classes are perfect for anyone who wants a jump start in learning Suricata or who wants a more thorough understanding of it internals.

### Suricata is intrusion detection and prevention system

> Suricata is a free and open source, mature, fast and robust network threat detection engine. The Suricata engine is capable of real time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM) and offline pcap processing.

## Day 0 :: Intro:: Feb 12 2018, starts at 13:00

 * 13:00 - 14:45
   * [Intro](/common/day_intro.md)
   * [what is Suricata](/Suricata/suricata/README.md)
   * [vagrant](/common/vagrant.intro.md)
   * [singlehost](/Suricata/vagrant/singlehost/)
 * 15:00 - 16:45
   * [intro to rules](/Suricata/rules/rules.intro.md)
   * [intro to dashboarding]()

## Day 1 :: Single Box :: Feb 13 2018

 * 09:00 - 12:30
   * [build from source](/Suricata/setup/build.md)
   * [config](/Suricata/setup/config.md)
 * 13:30 - 16:45
   * [rules, cont.](/Suricata/rules), [playing with config](/Suricata/setup/config.md)
   * [elasticsearch](/common/elastic), [install](/common/elastic/elastic.install.md), [mappings](/common/elastic/elastic.mappings.md)
   * [evebox](/Suricata/evebox)
   * [scirius](/Suricata/scirius)

## Day 2 :: Scale up :: Feb 14 2018

* 09:00 - 12:30
  * [multihost with](/Suricata/vagrant/multihost) [salt](/common/salt)
  * [rules management](/Suricata/rules/rules.update.md)

* 13:30 - 16:45
  * [elastic, clustered](/common/elastic/elastic.cluster.md)
  * [indexing alert log](/Suricata/logging/)
  * [Dashboarding and aggregations](/common/kibana.md)

## Day 3 :: Usage :: Feb 15 2018

* 09:00 - 12:30
  * [indexing alert log](/Suricata/logging/)
  * [Suricata unix socket](/Suricata/suricata/unixsocket.md)
  * [Suricata loading pcaps](/Suricata/suricata/LoadPcaps.md)
* 13:30 - 16:45
  * [Suricata LUA](/Suricata/lua)

## Day +1 :: :: Feb 16 2018, ends at 12:00

* 09:00 - 10:30
  * [IPS](/Suricata/suricata/ips-intro.md)
  * [feedback, contact exchange, thanks, etc.](/common/Closing.md)

----

Before You Come To Class please browse trough ..

* [Suricata](/Suricata/suricata/README.md)
* [Scirius](/Suricata/scirius/README.md)
* [Evebox](/Suricata/evebox/README.md)
