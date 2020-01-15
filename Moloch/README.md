
This material has been designed to be taught in a [classroom](https://ccdcoe.org/training/cyber-defence-monitoring-course-module-3/) environment... hands-on 80% + talk 40% + **slides 0%** = 120% hard work

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Moloch. We believe these classes are perfect for anyone who wants a jump start in learning Moloch or who wants a more thorough understanding of it internals.

### Moloch is a large scale, open source, full packet capturing, indexing, and database system.
> Moloch is not meant to replace Intrusion Detection Systems (IDS). Moloch augments your current security infrastructure by storing and indexing network traffic in standard PCAP format, while also providing fast indexed access.

# LS20 PCAP workshop June 1 - June 5 

## Day 0 :: Intro, single box :: June 1 2020, starts at 13:00!

 * 13:00 - 17:00 
   * [Intro](/common/day_intro.md)
   * [vagrant](/common/vagrant/), [docker](/common/docker)
   * [singlehost](/Moloch/singlehost/)

## Day 1 :: Building, Labeling the traffic :: June 2 2020

 * 09:00 - 12:30
   * [build from source](/Moloch/setup/#Build), [basic config](/Moloch/setup/#Config)
   * [build + config, cont](/Moloch/setup), [Basic digging](/Moloch/queries/#using-the-viewer)
   * [Moloch API intro](/Moloch/queries/#api)

 * 13:30 - 17:00 
   * [Hunting trip, web](/Moloch/queries/#hunting-trip)
   * [WISE - basic usage](/Moloch/wise#using-simple-plugins)

## Day 2 :: Group up, scale out :: June 3 2020

 * 09:00 - 12:30 
   * [WISE - Plugins](/Moloch/wise#writing-a-wise-plugin)

 * 13:30 - 17:00 
   * [Clustered elastic](/Moloch/clustering#clustered-elasticsearch), [multinode](/Moloch/clustering#moloch-workers)

## Day 3 :: Cross-class cluster, performance tuning :: June 4 2020
  
 * 09:00 - 12:30 
   * [Clustering teamwork, cont](/Moloch/clustering)
   * [Hunting trip, client-side](/Moloch/queries/#hunting-trip)
 * 13:30 - 16:45 
   * [feedback, contact exchange, thanks, etc.](/common/Closing.md)

## Day +1 :: Last but not least :: June 5 2020, ends at 12:00

 * 09:00 - 11:00
   * [Hunting trip, network](/Moloch/queries/#hunting-trip)
   * [load pcap via unix socket](/Suricata/unix-socket)
   * [evebox](/Suricata/indexing#evebox), [scirius](/Suricata/indexing#scirius), [kibana](/Suricata/indexing#kibana)
 * 11:00 - 12:00
   * [feedback, contact exchange, thanks, etc.](/common/Closing.md)

----

# Before You Come To Class

  * [Prepare your laptop](/Moloch/prepare-laptop.md)
  * browse trough ...
  * [molo.ch](http://molo.ch/)
  * [moloch FAQ](https://github.com/aol/moloch/wiki/FAQ)
  * [moloch wiki](https://github.com/aol/moloch/wiki)
  * [InfoSec matters - Moloch FPC](http://blog.infosecmatters.net/2017/05/moloch-fpc.html)
