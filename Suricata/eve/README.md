# Extensible Event Format (EVE)

* https://suricata.readthedocs.io/en/latest/quickstart.html#eve-json

## Parse a PCAP file offline

Suricata has `-r` for pcap read mode. Likewise, logging directory can be overridden with `-l`. Nite that `--disable-detection` is used to avoid Suricata complaining about missing rulesets. Don't worry, that topic will be covered later. For now, we just want to explore protocol logs.

```
./bin/suricata -r $PCAP -l $LOG_DIR --disable-detection
```

You should find `eve.json` file in `$LOG_DIR`.

```
cat $LOG_DIR/eve.json
```

## Using jq to work with EVE

`jq` is your friend.

```
cat $LOG_DIR/eve.json | jq .
```

You can use dot notation to access specific fields.

```
cat $LOG_DIR/eve.json | jq .event_type
```

`jq` syntax can be a rocket ship. But don't be afraid to use some bash pipes to help you out. **Start with high level view.**

* use `jq` to extract interesting field
* pipe to `sort` to get ordered list
* pipe to `uniq` to only extract unique values, `-c` flag outputs counts
* pipe to `sort` again to sort by count

```
cat logs/eve.json| jq .event_type | .tls.sni'  |sort -h | uniq -c | sort -h
cat logs/eve.json| jq .src_ip | .tls.sni'  |sort -h | uniq -c | sort -h
cat logs/eve.json| jq .dest_ip | .tls.sni'  |sort -h | uniq -c | sort -h
```

What is *interesting field*? You need to discover this for yourself. But always start with `event_type`. Each distinct `event_type` has it's own structure (which depends on config, more on that alter).

`jq` has `select` clause to filter by value. For example, suppose you want to extract all `tls` events.

```
cat logs/eve.json| jq 'select(.event_type=="tls")'
```

Boom, only `tls` events in console. But remember that `jq` is a rocket ship. Can it pipe, why yes, yes it can!

```
cat logs/eve.json| jq 'select(.event_type=="tls") | .tls.sni'
```

Not that final pipe is not part of bash syntax, it's from `jq` itself. The example command extracts all `sni` fields from `tls` struct. *Server Name Identifier* is a TLS extension for presenting domain to web server, usually used in vhost configuration for presenting different certificates based on requested domain.

Like before, next step is to build a list of all unique values.

```
cat logs/eve.json| jq 'select(.event_type=="tls") | .tls.sni' | sort -h | uniq -c | sort -h
```

And drill down on any values that seem interesting.

```
cat logs/eve.json| jq 'select(.tls.sni=="interesting.berylia.org")'
```

Or exclude boring values. `jq` pipe is used as negating would otherwise include unapplicable logs. For example, `smb` event does not have `tls` struct, so it would match a negated query.

```
cat logs/eve.json| jq 'select(.event_type=="tls") | select(.tls.sni!="boring.berylia.org")'
```

Exclusion is actually a nice trick. For example, why not drop the most common protocols and see if anything weird pops up?

```
cat logs/eve.json| jq 'select(.event_type=="tls") | select(.tls.version!="TLS 1.2")'
```

Rinse and repeat.

```
cat logs/eve.json| jq 'select(.event_type=="tls") | select(.tls.sni!="boring.berylia.org") | .tls.sni ' | sort | uniq -c | sort -h
```

Lists can be unpacked with `.[]`. 

```
cat logs/eve.json| jq 'select(.event_type=="dns") | .dns.answers' | grep -v null | jq '.[]'
```

Multiple fields can be extracted by separating them with comma.

```
cat logs/eve.json| jq 'select(.event_type=="http") | .timestamp , .http.hostname , .http.url'
```

## Tasks

Select malware traffic analysis PCAP and:
* Parse it with suricata to generate `eve.json`
* Extract all unique 
  * event types
  * source and destination IP addresses
  * protocols
  * application protocols
* Drill down on `dns` **queries**
  * build a top list of all unique queries
  * does anything pop out?
  * if it does, what are associated IP responses and has that IP done anything else?
