
This material has been designed to be taught in a [classroom](https://ccdcoe.org/training/cyber-defence-monitoring-course-large-scale-packet-capture-analysis-2/) environment... hands-on 80% + talk 40% + **slides 0%** = 120% hard work

**The online material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **3.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Arkime. We believe these classes are perfect for anyone who wants a jump start in learning Arkime or who wants a more thorough understanding of it internals.

### Arkime is a large scale, open source, full packet capturing, indexing, and database system.

> Arkime was formerly named **Moloch**, so the materials on this site may still refer to it as Moloch in various ways or forms. Same holds true for the Arkime codebase.

> Arkime is not meant to replace Intrusion Detection Systems (IDS). Arkime augments your current security infrastructure by storing and indexing network traffic in standard PCAP format, while also providing fast indexed access.

NB! Provided timeline is preliminary and will develop according to the actual progress of the class. On-site participation only.

## Day 1 :: Intro, singlehost, basic Viewer usage :: June 12 2023, *starts at 11:00!*

 * 10:30 Registration open, coffee

 * 11:00 - 12:00
   * [Intro](/common/day_intro.md)
   * LS23 overview

 * 13:00 - 15:00
   * [Basic viewer and queries](/Arkime/queries/#using-the-viewer)
 * 15:30 - 17:00
   * [Hunting - LS RT Client Side](/Arkime/queries/#hunting-trip)
   * Intro to LS23 data capture

## Day 2 :: Install, configuration, basic enrichment :: June 13 2023

 * 09:30 - 10:30
   * [Singlehost](/singlehost/)
   * [Arkime setup](/Arkime/package_setup/)
 * 11:00 - 12:00
   * [Arkime setup, adding new fields](/Arkime/package_setup/)

 * 13:00 - 15:00
   * [Hunting - LS RT WEB](/Arkime/queries/#hunting-trip)
 * 15:30 - 17:00
   * [Hunting - Freeform](/Arkime/queries/#hunting-trip)

## Day 3 :: Enrichment, Monitoring encrypted traffic, SSL/TLS proxy :: June 14 2023

 * 09:30 - 10:30
   * [Suricata integration](/Arkime/suricata/)
 * 11:00 - 12:00
   * [Suricata integration](/Arkime/suricata/)

 * 13:00 - 15:00
   * [Hunting - LS RT NET continued](/Arkime/queries/#hunting-trip)
 * 15:30 - 17:00
   * [Polarproxy](/Arkime/polarproxy)
    
## Day +1 :: Last but not least :: June 15 2023, *ends at 12:30*

 * 09:30 - 10:30
   * Arkime rules
   * Splitting BT traffic
   * Free topics - NB! propose topics you would like to hear about!
   * Discussion of topics not covered in previous days
 * 11:00 - 12:00
   * [feedback, contact exchange, thanks, etc.](/common/Closing.md)
 

## Orphan topics, topics from previous iterations that we might or might not cover.
   * [Pikksilm](/Arkime/pikksilm)
   * [vagrant](/common/vagrant/), [docker](/common/docker)
     * [Prepare your laptop](/Arkime/prepare-laptop.md)
   * [build from source](/Arkime/setup/#Build), [basic config](/Arkime/setup/#Config)
   * [WISE - Plugins](/Arkime/wise#writing-a-wise-plugin)
   * [Clustered elastic](/Arkime/clustering#clustered-elasticsearch), [multinode](/Arkime/clustering#moloch-workers)
   * [Clustering teamwork, cont](/Arkime/clustering)
   * [evebox](/Suricata/indexing#evebox), [scirius](/Suricata/indexing#scirius), [kibana](/Suricata/indexing#kibana)

----

# Before You Come To Class

  * browse trough ...
  * [Arkime](https://arkime.com/)
  * [Arkime in GitHub](https://github.com/arkime/arkime)
  * [Arkime FAQ](https://arkime.com/faq)
  * [Arkime learn](https://arkime.com/learn)
  * [InfoSec matters - Arkime FPC](http://blog.infosecmatters.net/2017/05/moloch-fpc.html)
