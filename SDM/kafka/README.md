# Apache Kafka

## Key concepts

> Apache Kafka is a distributed streaming platform.

> Kafka can be run as a single instance node, but it is meant to run as a cluster on one or more servers.

> Kafka stores streams of records in categories called 'topics'.

> Kafka relies on [ZooKeeper](https://zookeeper.apache.org/) to cooridinate its distributed cluster.

See: 

* https://kafka.apache.org/intro

## Setup

Kafka has a pretty good quickstart guide. 

See:

  * https://kafka.apache.org/quickstart

## Kafka's own scripts

Kafka comes bundled with a set of shell scripts that can be used to interact with the Kafka cluster. They are simple shell scripts which actually start Java to run some specific Java class which thenin turn interacts with the Kafka cluster.

* These scripts can be found in the 'bin' directory of your Kafka installation.

```
connect-distributed.sh        kafka-console-consumer.sh    kafka-log-dirs.sh                    kafka-replay-log-producer.sh   kafka-simple-consumer-shell.sh      trogdor.sh
connect-standalone.sh         kafka-console-producer.sh    kafka-mirror-maker.sh                kafka-replica-verification.sh  kafka-streams-application-reset.sh  zookeeper-security-migration.sh
kafka-acls.sh                 kafka-consumer-groups.sh     kafka-preferred-replica-election.sh  kafka-run-class.sh             kafka-topics.sh                     zookeeper-server-start.sh
kafka-broker-api-versions.sh  kafka-consumer-perf-test.sh  kafka-producer-perf-test.sh          kafka-server-start.sh          kafka-verifiable-consumer.sh        zookeeper-server-stop.sh
kafka-configs.sh              kafka-delete-records.sh      kafka-reassign-partitions.sh         kafka-server-stop.sh           kafka-verifiable-producer.sh        zookeeper-shell.sh
```

### Create a new topic

### What topics exist?

### Send messages (producer)

### Receive message (consumer)


