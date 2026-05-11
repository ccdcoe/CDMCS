This material has been designed to be taught in a [classroom](https://ccdcoe.org/training/cyber-defence-monitoring-course-large-scale-packet-capture-analysis-june-2026/) environment... hands-on 80% + talk 40% + **slides 0%** = 120% hard work

**The online material is missing some of the contextual concepts and ideas that will be covered in class.**

This course holds **~5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Arkime. We believe these classes are perfect for anyone who wants a jump start in learning Arkime or who wants a more thorough understanding of it internals. 

Analyzing the most recent Locked Shields dataset is an added bonus all participants get. Furthermore, in the class we've also had dedicated session by LS red teamers shining a light on what sneaky things they did in the recent exercise.

### Arkime is a large scale, open source, full packet capturing, indexing, and database system

> Arkime was formerly named **Moloch**, so the materials on this site may still refer to it as Moloch in various ways or forms. Same holds true for the Arkime codebase.
> Arkime is not meant to replace Intrusion Detection Systems (IDS). Arkime augments your current security infrastructure by storing and indexing network traffic in standard PCAP format, while also providing fast indexed access.

**Provided timeline is preliminary and will develop according to the actual progress of the class. On-site participation only.**

**Attention:** Initial start time of 13:00 has changed to **09:00** as communicated via e-mail.

## Day 1 :: Intro, singlehost, basic Viewer usage :: June 15 2026 :: 09:00 Local time

* 08:30 Registration open

* 09:00 - 17:00
  * [Intro](/common/day_intro.md)
  * [Singlehost](/singlehost/)
  * LS26 overview
  * [Basic viewer and queries](/Arkime/queries/#using-the-viewer)
  * [Alkeme](https://arkime.com/alkeme) - A Terminal UI for Arkime
  * Intro to LS26 data capture
  * Splitting LS BT traffic

## Day 2 :: Install, basic configuration :: June 16 2026

* 09:00 - 17:00
  * [Arkime setup](/Arkime/package_setup/)
  * [basic config](/Arkime/setup/#Config)
  * [Hunting - RT Web](/Arkime/queries/#hunting-trip)

## Day 3 :: Advanced configuration, enrichment :: June 17 2026

* 09:00 - 17:00
  * [Arkime setup, adding new fields](/Arkime/package_setup/)
  * [MISP integration](/Arkime/misp_wise/)
  * [Suricata integration](/Arkime/suricata/)
  * [Suricata](/Suricata)

## Day 4 :: Suricata, SSL/TLS proxy :: June 18 2026

* 09:00 - 17:00
  * [Suricata rules](/Suricata/rules), [suricata-update](/Suricata/suricata-update)
  * [Suricata datasets](/Suricata/datasets)
  * [Hunting - RT client side](/Arkime/queries/#hunting-trip)
  * [Polarproxy](/Arkime/polarproxy)
    
## Day 5 :: Last but not least :: June 19 2026, *ends at 12:00*

* 09:30 - 12:00
  * [Hunting - RT Net](/Arkime/queries/#hunting-trip)
  * [feedback, contact exchange, thanks, etc.](/common/Closing.md)
 

## Orphan topics, topics from previous iterations that we might or might not cover

* [build from source](/Arkime/setup/#Build)
* [Pikksilm](/Arkime/pikksilm)
* [WISE - Plugins](/Arkime/wise#writing-a-wise-plugin)
* [Clustered elastic](/Arkime/clustering#clustered-elasticsearch), [multinode](/Arkime/clustering#moloch-workers)
* [Clustering teamwork, cont](/Arkime/clustering)
* [evebox](/Suricata/indexing#evebox), [scirius](/Suricata/indexing#scirius), [kibana](/Suricata/indexing#kibana)

## For trying out locally -- *not needed for classroom!*

* [vagrant](/common/vagrant/), [docker](/common/docker)
  * [Prepare local environment](/Arkime/prepare-laptop.md)

----

# Before You Come To Class

* browse trough ...
* [Arkime](https://arkime.com/)
* [Arkime in GitHub](https://github.com/arkime/arkime)
* [Arkime FAQ](https://arkime.com/faq)
* [Arkime learn](https://arkime.com/learn)
* [InfoSec matters - Arkime FPC](http://blog.infosecmatters.net/2017/05/moloch-fpc.html)
