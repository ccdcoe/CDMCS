
This material has been designed to be taught in a [classroom](https://ccdcoe.org/training/cyber-defence-monitoring-course-rule-based-threat-detection/) environment... hands-on 80% + talk 40% + **slides 0%** = 120% hard work 

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Suricata. We believe these classes are perfect for anyone who wants a jump start in learning Suricata or who wants a more thorough understanding of it internals.

## Suricata is intrusion detection and prevention system

> Suricata is a free and open source, mature, fast and robust network threat detection engine. The Suricata engine is capable of real time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM) and offline pcap processing.

# Suricata 

## Day 0: Intro - Mon, Oct 17, *starts at 11:00*

 * 11:00 - 12:30
   * [Intro](/common/day_intro.md)
   * [singlehost](/singlehost)
   * [vagrant](/Suricata/vagrant)
   * [what is Suricata](/Suricata/intro)
 * 13:30 - 16:30
   * [Suricata on CLI](/Suricata/intro)
   * [writing your first rule](/Suricata/intro#writing-your-first-rule)

## Day 1 - Tue, Oct 18, 08:30
 * 08:30 - 12:30
   * [EVE log basics](/Suricata/eve)
   * [EVE basic tasks](/Suricata/eve#tasks)
   * [rule writing, cont](/Suricata/rules)
 * 13:30 - 16:30
   * [Ruleset exploration show and tell](/Suricata/rulesets#show-and-tell)
   * [Unix socket mode](/Suricata/unix-socket)
   * [Introducing rulesets](/Suricata/rulesets)
   * [suricata-update](/Suricata/suricata-update)

## Day 2 - Wed, Oct 19, 08:30
 * 08:30 - 12:30
   * [building suricata](/Suricata/build)
   * [live capture and replay](/Suricata/live)
   * [configuring suricata](/Suricata/config)
 * 13:30 - 16:30
   * [configuring suricata](/Suricata/config)
   * [datasets](/Suricata/datasets)
   * [lua scipting](/Suricata/lua)

## Day 3 - Thu, Oct 20, 08:30
 * 08:30 - 12:30
   * [Elastic intro](/Suricata/elastic), 
   * [Log shipping](/Suricata/elastic-log-shipping)
   * [Kibana and Evebox](/Suricata/frontend)
 * 13:30 - 16:30
   * [SELKS](/Suricata/selks)
   * [Hunting notebooks](/Suricata/selks#suricata-analytics)

## Day +1: Last but not least - Fri, Oct 21, 08:30
 * 08:30 - 10:00
   * [open for requests](/Suricata)
 * 10:30 - 11:30
   * [feedback, contact exchange, thanks, etc.](/common/Closing.md)

### Before You Come To Class please browse trough ..

 * [prereqs](https://github.com/ccdcoe/CDMCS/tree/master/prerequisites)
 * [singlehost](https://github.com/ccdcoe/CDMCS/tree/master/singlehost)
 * [suricata](https://suricata.readthedocs.io/en/latest/)
 * [vagrant](https://github.com/ccdcoe/CDMCS/tree/master/common/vagrant)
