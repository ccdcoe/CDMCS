
This material has been designed to be taught in a [classroom](https://ccdcoe.org/training/cyber-defence-monitoring-course-module-3/) environment... hands-on 80% + talk 40% + **slides 0%** = 120% hard work

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Arkime. We believe these classes are perfect for anyone who wants a jump start in learning Arkime or who wants a more thorough understanding of it internals.

### Arkime is a large scale, open source, full packet capturing, indexing, and database system.

> Arkime was formerly named **Moloch**, so the materials on this site may still refer to it as Moloch in various ways or forms. Same holds true for the Arkime backend code, etc.

> Arkime is not meant to replace Intrusion Detection Systems (IDS). Arkime augments your current security infrastructure by storing and indexing network traffic in standard PCAP format, while also providing fast indexed access.

Provided timeline is preliminary and will develop according to the actual progress of the class.

* NB! The schedule is tentative and subject to change. On-site participation only, so the course depends entirely on the COVID-19 situation at the time. *

## Day 0 :: Intro, singlebox, basic Viewer :: Jun 13 2022, *starts at 13:00!*

 * 13:00 - 17:00
   * [Intro](/common/day_intro.md)
   * LS22 overview and intro
   * [singlehost](/singlehost/)
   * [Basic digging](/Arkime/queries/#using-the-viewer)

## Day 1 :: Config, API, basic tags :: June 14 2022

 * 09:30 - 12:30
   * [basic config](/Arkime)
   * [Arkime API intro](/Arkime/queries/#api)
   * [WISE - basic usage](/Arkime/wise#using-simple-plugins)

 * 13:30 - 17:00
   * [Hunting trip - RT](/Arkime/queries/#hunting-trip)

## Day 2 :: Labelling the traffic, data enrichment :: June 15 2022

 * 09:30 - 12:30
   * [WISE - Plugins](/Arkime/wise#writing-a-wise-plugin)
   * [Pikksilm](https://github.com/markuskont/pikksilm)

 * 13:30 - 17:00
   * [Hunting trip - RT](/Arkime/queries/#hunting-trip)
    

## Day 3 :: Cross-class cluster, performance tuning :: June 16 2022

 * 09:30 - 12:30
   * [Hunting trip - RT](/Arkime/queries/#hunting-trip)
 
 * 13:30 - 17:00
   * Advanced topics - propose topics you would like to hear about

## Day +1 :: Last but not least :: June 17 2022, *ends at 12:00*

 * 09:30 - 11:00
   * [Hunting trip - RT](/Arkime/queries/#hunting-trip)
 * 11:00 - 12:00
   * [feedback, contact exchange, thanks, etc.](/common/Closing.md)


## Orphan topics, topics from previous iterations that we might or might not cover.
   * [vagrant](/common/vagrant/), [docker](/common/docker)
   * [build from source](/Arkime/setup/#Build), [basic config](/Arkime/setup/#Config)
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
