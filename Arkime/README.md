
This material has been designed to be taught in a [classroom](https://ccdcoe.org/training/cyber-defence-monitoring-course-large-scale-packet-capture-analysis/) environment... hands-on 80% + talk 40% + **slides 0%** = 120% hard work

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Arkime. We believe these classes are perfect for anyone who wants a jump start in learning Arkime or who wants a more thorough understanding of it internals.

### Arkime is a large scale, open source, full packet capturing, indexing, and database system.

> Arkime was formerly named **Moloch**, so the materials on this site may still refer to it as Moloch in various ways or forms. Same holds true for the Arkime codebase.

> Arkime is not meant to replace Intrusion Detection Systems (IDS). Arkime augments your current security infrastructure by storing and indexing network traffic in standard PCAP format, while also providing fast indexed access.

NB! Provided timeline is preliminary and will develop according to the actual progress of the class. On-site participation only, on-site regulations depend on the COVID-19 situation at the time.

## Day 0 :: Intro, singlehost, basic Viewer :: June 13 2022, *starts at 13:00!*

 * 12:30 Registration open

 * 13:00 - 17:00
   * [Intro](/common/day_intro.md)
   * LS22 overview and intro
   * [Singlehost](/singlehost/)
   * [Basic viewer and queries](/Arkime/queries/#using-the-viewer)

## Day 1 :: Install, config, basic enrichment :: June 14 2022

 * 09:30 - 12:30
   * [Arkime setup](/Arkime/package_setup/)

 * 13:30 - 17:00
   * [Hunting - RT (WEB)](/Arkime/queries/#hunting-trip)

## Day 2 :: Monitoring encrypted traffic, SSL/TLS proxy :: June 15 2022

 * 09:30 - 12:30
   * [Arkime setup, adding new fields](/Arkime/package_setup/)
   * [Polarproxy](/Arkime/polarproxy)

 * 13:30 - 17:00
   * [Hunting - RT (NET)](/Arkime/queries/#hunting-trip)
    

## Day 3 :: Advanced enrichment, detecting beacons :: June 16 2022

 * 09:30 - 12:30
   * [Winlogbeat](https://www.elastic.co/beats/winlogbeat)
   * [Pikksilm](https://github.com/markuskont/pikksilm)
 
 * 13:30 - 17:00
   * [Hunting - RT (5G)](/Arkime/queries/#hunting-trip)

## Day +1 :: Last but not least :: June 17 2022, *ends at 12:00*

 * 09:30 - 11:00
   * Free topics - propose topics you would like to hear about
   * [Hunting - RT (TBD)](/Arkime/queries/#hunting-trip)
 * 11:00 - 12:00
   * [feedback, contact exchange, thanks, etc.](/common/Closing.md)


## Orphan topics, topics from previous iterations that we might or might not cover.
   * [vagrant](/common/vagrant/), [docker](/common/docker)
   * [build from source](/Arkime/setup/#Build), [basic config](/Arkime/setup/#Config)
   * [WISE - Plugins](/Arkime/wise#writing-a-wise-plugin)
   * [Clustered elastic](/Arkime/clustering#clustered-elasticsearch), [multinode](/Arkime/clustering#moloch-workers)
   * [Clustering teamwork, cont](/Arkime/clustering)
   * [load pcap via unix socket](/Suricata/unix-socket)
   * [evebox](/Suricata/indexing#evebox), [scirius](/Suricata/indexing#scirius), [kibana](/Suricata/indexing#kibana)

----

# Before You Come To Class

  * [Prepare your laptop](/Arkime/prepare-laptop.md)
  * browse trough ...
  * [Arkime](https://arkime.com/)
  * [Arkime in GitHub](https://github.com/arkime/arkime)
  * [Arkime FAQ](https://arkime.com/faq)
  * [Arkime learn](https://arkime.com/learn)
  * [InfoSec matters - Arkime FPC](http://blog.infosecmatters.net/2017/05/moloch-fpc.html)
