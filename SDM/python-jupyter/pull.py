#!/usr/bin/env python

from kafka import KafkaConsumer
import json

topic = "cee"
server = "localhost:9092"

consumer = KafkaConsumer(topic, group_id=None, bootstrap_servers=server, auto_offset_reset='earliest')
with open("dump.log", "w") as f:
    for msg in consumer:
        f.write(str(msg.partition) + msg.value.decode("utf-8") + "\n")
        #print(msg.value.decode("utf-8"))
