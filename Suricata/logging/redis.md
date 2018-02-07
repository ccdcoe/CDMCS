# redis

* https://redis.io/topics/quickstart

```
filetype: redis #regular|syslog|unix_dgram|unix_stream|redis
redis:
  server: 127.0.0.1
  port: 6379
  async: true ## if redis replies are read asynchronously
  mode: list ## possible values: list|lpush (default), rpush, channel|publish
             ## lpush and rpush are using a Redis list. "list" is an alias for lpush
             ## publish is using a Redis channel. "channel" is an alias for publish
  key: suricata ## key or channel to use (default to suricata)
  pipelining:
    enabled: yes ## set enable to yes to enable query pipelining
    batch-size: 10 ## number of entry to keep in buffer
```
