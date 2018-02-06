#!/usr/bin/env python3

import sys
from elasticsearch import Elasticsearch
import csv, json

JSON_PATH = '/vagrant/data/apache.log.1'

BULKSIZE=1024

INDEX='apache-2016.12'
TYPE='logs'
PIPELINE='apache'
TPL= {
    "settings" : {
        "number_of_shards" : 1,
        "number_of_replicas" : 0
    }
}

def main():
    es = Elasticsearch(timeout=60)
    es.indices.create(index=INDEX, ignore=400)

    with open(JSON_PATH) as f:
        i = 0
        count = 0
        batch = []
        for line in f:
            meta = {
                "index": {
                    '_index': INDEX,
                    '_type': TYPE
                }
            }
            source = {
                'message': line
            }
            batch.append(json.dumps(meta))
            batch.append(json.dumps(source))
            if i % BULKSIZE == 0:
                batch = '\n'.join(batch)
                stats = es.bulk(body=batch, pipeline=PIPELINE)
                batch = []
                print('Bulk: ',i)
            i += 1
        es.bulk(body=batch)

if __name__ == '__main__':
    main()
