# Intro

## Why

* So, why build if we can install?
* Each env in different, each org has its own policies and setup;
* Goal is to understand how Suricata is set up, what goes in;
* must understand when debugging;
* for analysts: garbage in -> garbage out;
    * even if you won't build your own, you need to understand input;
    * you don't see something, could be packet loss, overloaded rule, missing features;
    * you need to explain WHY you did not find the bad thing;
    * you need to propose how to debug rulesets, configs, etc;
    * might not be able to do that without custom builds;
    * remember, one rule can kill your performance;
* custom build in prod;
    * could be prohibited by policy;
    * that's backward thinking (for OSS);
    * custom build == code audit == protect against supply chain attack;
    * one big central IDS is pretty common, needs to optimize;
* Why NOT to run custom build in prod;
    * policy prohibits, no resources to audit code;
    * many probes, distributed, needs deploy system and central management;
