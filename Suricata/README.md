
This material has been designed to be taught in a [classroom](https://ccdcoe.org/training/cyber-defence-monitoring-course-module-1/) environment... hands-on 80% + talk 40% + **slides 0%** = 120% hard work 

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn Suricata. We believe these classes are perfect for anyone who wants a jump start in learning Suricata or who wants a more thorough understanding of it internals.

### Suricata is intrusion detection and prevention system

> Suricata is a free and open source, mature, fast and robust network threat detection engine. The Suricata engine is capable of real time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM) and offline pcap processing.

# Suricata Remote

## Week 1

### Session 1
 * [Intro](/common/day_intro.md)
 * [singlehost, vagrant](/singlehost)
 * [what is Suricata](/Suricata/rules#intro)
 <!-- * [tooling intro - docker / jupyter]() -->
 * [first rule, suricata -R ...]()

### Session 2
 * [EVE log, jq magics, bash sorting]()
 * [EVE log tasks, MTA pcap]()
     * extract N fields
 * [tcpreplay / live capture]()
 * [second rule]()

### Session 3
 * [Rulesets dataframe/notebook show and tell]()
 * [MTA data exploration, EVE JSON explore]()
     * [task - building a timeline of attacks / write simple report]()
 * [suricata-update]()

## Week 2

### Session 4
 * [building suricata]()
    * [profiling ruleset]()
 * [suricata.yaml]()

### Session 5
 * [datasets]()
 * [lua (talk)]()

### Session 6
 * [docker run elasticsearch?]()
 * [shipper notebook / what is bulk api / logstash config and filebeat config]()
 * [evebox, kibana]()
