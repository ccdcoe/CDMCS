
This material has been designed to be taught in a [classroom](https://ccdcoe.org/training/cyber-defence-monitoring-course-suite-module-3-apr-2019/) environment... hands-on 90% talk 10% **slides 0%**

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Moloch. We believe these classes are perfect for anyone who wants a jump start in learning Moloch or who wants a more thorough understanding of it internals.

### Moloch is a large scale, open source, full packet capturing, indexing, and database system.
> Moloch is not meant to replace Intrusion Detection Systems (IDS). Moloch augments your current security infrastructure by storing and indexing network traffic in standard PCAP format, while also providing fast indexed access.

# Mobile course May 27 - May 31

## Day 0 :: Intro:: May 27 2019, starts at 13:00

  * 13:00 - 16:45
    * [Intro](/common/day_intro.md)
    * [vagrant](/common/vagrant/), [docker](/common/docker)
    * [singlehost](/Moloch/singlehost/)

## Day 1 :: Single box, setting up :: May 28 2019

 * 09:00 - 12:30 
    * [build from source](/Moloch/setup/#Build)
    * [basic config](/Moloch/setup/#Config)

 * 13:30 - 17:00 
    * [Basic queries](/Moloch/queries/#using-the-viewer)
    * [Moloch API](/Moloch/queries/#api)

## Day 2 :: Threat intel, hipster tech :: May 29 2019

 * 09:00 - 12:30 
    * [Rule format](https://github.com/aol/moloch/wiki/RulesFormat)
    * [WISE - basic usage](/Moloch/wise#using-simple-plugins)

 * 13:30 - 17:00 
    * [WISE - Plugins](/Moloch/wise#writing-a-wise-plugin)

## Day 3 :: Group up, scale out :: May 30 2019

 * 09:00 - 12:30 
    * [Clustered elastic](/Moloch/clustering#clustered-elasticsearch)
    * [multinode](/Moloch/clustering#moloch-workers)
 * 13:30 - 17:00 
    * [Clustering teamwork, cont](/Moloch/clustering)
    * [scaling the capture](/Moloch/tuning)

## Day +1 :: Encore :: May 31 2019, ends at 12:00

 * 09:00 - 11:00
   * Insert topics here

 * 11:00 - 12:00
   * [feedback, contact exchange, thanks, etc.](/common/Closing.md)

# LS19 workshop April 23 - April 26

**NB! Note that that due to public holidays, we are unconventionally staring our course on Tuesday at 09:00 and working until Friday afternoon.**

## Day 1 :: Intro, single box, building :: April 23 2019, starts at 09:00!

 * 09:00 - 12:30 
    * [Intro](/common/day_intro.md)
    * [vagrant](/common/vagrant/), [docker](/common/docker)
    * [singlehost](/Moloch/singlehost/)
    * [build from source](/Moloch/setup/#Build), [basic config](/Moloch/setup/#Config)
 * 13:30 - 17:00 
    * [build + config, cont](/Moloch/setup), [Basic digging](/Moloch/queries/#using-the-viewer)

## Day 2 :: Labeling the traffic :: April 24 2019

  * 09:00 - 12:30
    * [Moloch API intro](/Moloch/queries/#api)
    * [Hunting trip, web](/Moloch/queries/#hunting-trip)

  * 13:30 - 17:00 
    * [WISE - basic usage](/Moloch/wise#using-simple-plugins)

## Day 3 :: Group up, scale out :: April 25 2019

  * 09:00 - 12:30 
    * [WISE - Plugins](/Moloch/wise#writing-a-wise-plugin)

  * 13:30 - 17:00 
    * [Clustered elastic](/Moloch/clustering#clustered-elasticsearch), [multinode](/Moloch/clustering#moloch-workers)

## Day 4 :: Cross-class cluster, performance tuning :: April 26 2019, **ends at 17:00**
  
  * 09:00 - 12:30 
    * [Clustering teamwork, cont](/Moloch/clustering)
    * [Hunting trip, client-side](/Moloch/queries/#hunting-trip)
  * 13:30 - 16:45 
    * [Hunting trip, network](/Moloch/queries/#hunting-trip)
    * [feedback, contact exchange, thanks, etc.](/common/Closing.md)

----

# Before You Come To Class

  * [Prepare your laptop](/Moloch/prepare-laptop.md)
  * browse trough ...
  * [molo.ch](http://molo.ch/)
  * [moloch FAQ](https://github.com/aol/moloch/wiki/FAQ)
  * [moloch wiki](https://github.com/aol/moloch/wiki)
  * [InfoSec matters - Moloch FPC](http://blog.infosecmatters.net/2017/05/moloch-fpc.html)
