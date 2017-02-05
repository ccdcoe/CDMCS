
This material has been designed to be taught in a [classroom](https://ccdcoe.org/cyber-defence-monitoring-course-suite-module-2-0.html) environment... hands-on 90% talk 10% **slides 0%**

**The material is missing some of the contextual concepts and ideas that will be covered in class.**

This is **0.5 + 3 + 0.5 days** of material for any intermediate-level dev-ops who has some experience with other security|monitoring tools and wants to learn TICK+AG We believe these classes are perfect for anyone who wants a jump start in learning TICK, Alerta and Grafana or who wants a more thorough understanding of the three and their internals.

# TICK + A + G

> Time-Series ... actionable trends, patterns, variability, rates of change, covariation, cycles, exceptions, anomalies and outliers.

**TICK** is the purpose-built, end-to-end solution for collecting, storing, visualizing and alerting on time-series data at scale  
**Alerta** accepts alerts from the standard sources and does de-duplication and correlation  
**Grafana** is tool for querying and visualizing time series and metrics  


## Classroom
### Day 0 :: Intro:: Feb 13 2017 start at 13:00

 * 13:00 - 13:45 [Intro](/common/classroom/day_intro.md), [vagrant](/common/vagrant_intro.md)
 * 14:00 - 14:45 [singlehost](/TICK/vagrant/singlehost/README.md)
 * 15:00 - 15:45 [basic config](/TICK/classroom/day_intro/BasicConf.md)
 * 16:00 - 16:45 [basic visualisations](/TICK/classroom/day_intro/BasicVizs.md)

### [Day 1](/TICK/classroom/day_1/README.md) :: Single Box :: :: Feb 14 2017

 * 09:00 - 09:45 [Build  telegraf from source](/TICK/classroom/day_1/README.md#development-environment), [ add bind9 plugin](/TICK/classroom/day_1/README.md#adding-a-bind9-plugin-to-telegraf)
 * 10:00 - 10:45 [Telegraf config](/TICK/Telegraf/conf.md)
 * 11:00 - 11:45 [InfluxDB](/TICK/InfluxDB/README.md)


 * 13:00 - 13:45 [Chronograf](/TICK/Chronograf/README.md)
 * 14:00 - 14:45 [Kapacitor](/TICK/Kapacitor/README.md)
 * 15:00 - 15:45 [Alerta](/TICK/Alerta/README.md)
 * 16:00 - 16:45 [Grafana](/TICK/Grafana/README.md)


### Day 2 :: Scale up :: Feb 15 2017

* 09:00 - 09:45 [Minions](/common/SetUpMinions.md), [Master](/common/SetUpMaster.md),
* 10:00 - 10:45 [Influx CLI and queries](TICK/InfluxDB/cli.md)
* 11:00 - 11:45


* 13:00 - 13:45
* 14:00 - 14:45
* 15:00 - 15:45 Grafana
* 16:00 - 16:45


### Day 3 :: Usage :: Feb 16 2017

* 09:00 - 09:45 [eating numbers for breakfast](/TICK/classroom/day_3/README.md)
* 10:00 - 10:45 [eating log files](/TICK/classroom/day_1/logs2telegraf.md)
* 11:00 - 11:45


* 13:00 - 13:45 [UDF](/TICK/classroom/day_3/UDF.md)
* 14:00 - 14:45
* 15:00 - 15:45
* 16:00 - 16:45 Alerta

### Day +1 :: :: Feb 17 2017 end at 12:00

* 09:00 - 09:45 []()
* 10:00 - 10:45[]()
* 11:00 - 12:00[feedback, contact exchange, thanks, etc]()

---
## Before You Come To Class please browse trough ..

* [Telegraf](/TICK/Telegraf/README.md)
* [InfluxDB](/TICK/InfluxDB/README.md)
* [Chronograf](/TICK/Chronograf/README.md)
* [Kapacitor](/TICK/Kapacitor/README.md)
* [Alerta](/TICK/Alerta/README.md)
* [Grafana](/TICK/Grafana/README.md)
