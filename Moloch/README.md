
This material has been designed to be taught in a [classroom](https://ccdcoe.org/cyber-defence-monitoring-course-suite-module-3-1.html) environment... hands-on 90% talk 10% **slides 0%**

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Moloch. We believe these classes are perfect for anyone who wants a jump start in learning Moloch or who wants a more thorough understanding of it internals.

### Moloch is a large scale, open source, full packet capturing, indexing, and database system.
> Moloch is not meant to replace Intrusion Detection Systems (IDS). Moloch augments your current security infrastructure by storing and indexing network traffic in standard PCAP format, while also providing fast indexed access.

## Day 0 :: Intro:: May 7 2018, starts at 13:00

 * 13:00 - 14:00 
    * [Intro](/common/day_intro.md)
    * [vagrant](/common/vagrant.intro.md) 
    * [singlehost](/Moloch/vagrant/singlehost/)
 * 15:30 - 16:45 
    * [Basic usage](/Moloch/tasks/queries.md)

## Day 1 :: Single Box :: May 8 2018

 * 09:00 - 12:30 
    * [build from source](/Moloch/build.md)
    * [config](/Moloch/config.md)

 * 13:30 - 16:45 
    * Digging

## Day 2 :: Scale up :: May 9 2018

  * 09:00 - 12:30 
    * [Multihost](https://github.com/aol/moloch/wiki/Multiple-Host-HOWTO)
    * [Multiple Hosts Monitoring Multiple Network Segments](https://github.com/aol/moloch/wiki/Architecture#multiple-hosts-monitoring-multiple-network-segments)
    * [Parliament](https://github.com/aol/moloch/tree/master/parliament)
    * [Group work](/Moloch/vagrant/multihost/)

  * 13:30 - 16:45 
    * Digging

## Day 3 :: Usage :: May 10 2018

  * 09:00 - 12:30
    * [Moloch API](/Moloch/api.md)
    * [WISE](https://github.com/aol/moloch/wiki/WISE)
    * [High-bandwidth optimizations](/Moloch/optimize.md)

  * 13:30 - 16:45 
    * Digging

## Day +1 :: :: May 11 2018, ends at 12:00

  * 09:00 - 12:00
    * Propose what content you would like to see here
    * [feedback, contact exchange, thanks, etc.](/common/Closing.md)

----

# Before You Come To Class

* [Prepare your laptop](/Moloch/prepare-laptop.md)
* browse trough ...
  * [molo.ch](http://molo.ch/)
  * [moloch FAQ](https://github.com/aol/moloch/wiki/FAQ)
  * [moloch wiki](https://github.com/aol/moloch/wiki)
  * [Goodbye single host, woot!](https://github.com/aol/moloch/commit/8c472d939fad305d1c4134bde0ca8754faeaff84)
  * [InfoSec matters - Moloch FPC](http://blog.infosecmatters.net/2017/05/moloch-fpc.html)
