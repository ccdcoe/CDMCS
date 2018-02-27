# Apache Kafka

## Key concepts

* Apache Kafka is a distributed streaming platform.
* Kafka can be run as a single instance node, but it is meant to run as a cluster on one or more servers.
* Kafka stores streams of records in categories called 'topics'.
* Kafka relies on [ZooKeeper](https://zookeeper.apache.org/) to coordinate its distributed cluster.

See: 

* https://kafka.apache.org/intro

## Setup

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

```
bin/kafka-topics.sh --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic test
```

Or you could just have Kafka create a new topic when something is published into a non-existing topic. This is currently enabled by default.

```
auto.create.topics.enable=true
```

### See which topics exist

```
bin/kafka-topics.sh --list --zookeeper localhost:2181
```

### Send messages (producer)

```
bin/kafka-console-producer.sh --broker-list localhost:9092 --topic test
```

### Receive message (consumer)

```
bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic test --from-beginning
bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic test
```


### Change retention period

```
bin/kafka-topics.sh --zookeeper localhost:2181 --alter --topic test --config retention.ms=3600000
```

> Note: Temporarily altering the retention period is a nice way of deleting older messages in a topic without restarting the cluster.

### Kafka clients

In addition to the Java client, there are many others available.

See: https://cwiki.apache.org/confluence/display/KAFKA/Clients

### Custom clients

You can use available libraries to implement you own Kafka consumers and producers.


