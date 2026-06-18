# Datasets

* https://suricata.readthedocs.io/en/latest/rules/datasets.html

IDS rules have historically been rather static and self-contained entities. Threat detection, however, requires us to be dynamic and flexible. Consider [sslbl ja3 blacklist](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules) as an example. Each black or whitelisted hash needs to be separate rule with distinct ID. We could use PCRE with alternation, but that would kill our IDS performance. Best way to get around this limitation has been to generate those rules. While there is nothing wrong with this approach, it is still a hack around design limitations. Furthermore, entire ruleset needs to be reloaded if entries are added or removed from this list. 

`Datasets` is a new (ish) feature for eliminating this limitation. Any sticky buffer can be hooked to a list of base64 strings, md5, or sha256 hashes. `Datarep` is the same thing, but each entry can also be assigned a score. You can then define a threshold inside a rule, so it would trigger if reputation is above or below a numeric value.

## Suricata 8 — what changed (read this first)

This course runs **Suricata 8**. Datasets still work exactly as described below (sticky buffer +
`dataset` keyword + a list file), but three things bite if you follow the older 5/6/7 examples
verbatim. All of this is verified end-to-end on Suricata 8.0.5.

**1. Absolute paths are rejected by default.** A rule with `state /tmp/foo.lst` fails to load:
`detect-dataset: Absolute paths not allowed`. Enable them in `suricata.yaml`:

```
datasets:
  rules:
    allow-absolute-filenames: true
```

This is a config change, so **restart** Suricata (`systemctl restart suricata`) — `reload-rules`
alone won't pick it up.

**2. `state` / `save` may only write inside the data directory.** Keep your list files under the
Suricata data dir — use **`/var/lib/suricata/datasets/`** — and make them **owned by the `suricata`
user** so capture can both read the list and persist additions back to it:

```
sudo mkdir -p /var/lib/suricata/datasets
sudo chown -R suricata:suricata /var/lib/suricata/datasets
```

So in every example below, use a path like `/var/lib/suricata/datasets/<name>.lst` (not `/tmp/...`
or `/vagrant/...`) for `state` / `load`.

**3. `suricatasc` is on the `PATH`** (package install) — run `sudo suricatasc -c ...`, not
`./bin/suricatasc` as the older source-build examples show.

**4. EVE DNS logging changed in 8** — a query name is now under `dns.queries[].rrname` (the old
top-level `dns.rrname` is gone). This only affects how you *read* `eve.json`; the `dns.query` rule
keyword used below is unchanged.

## Basic usage with Suricata 5.0.x

`Dataset` can be created in `suricata.yaml` and then invoked in a rule.

```
datasets:
  defaults:
    memcap: 10mb
    hashsize: 1024
  ua-sha256:
    type: sha256
    state: /var/lib/suricata/useragents-sha256.lst
```

```
alert http any any -> any any (msg:"HTTP user-agent list"; http.user_agent; to_sha256; dataset:isset,ua-sha256; sid:123; rev:1;)
```

Alternatively, the rule could be rewritten to contain all needed parameters. Modifying `suricata.yaml` would not be needed in that case.

```
alert http any any -> any any (msg:"HTTP user-agent list"; http.user_agent; to_sha256; dataset:isset,ua-sha256,type sha256, state /var/lib/suricata/datasets/seen-dns.lst; sid:123; rev:1;)
```

## Basic usage with Suricata 6.0.x

All parameters can be set in the signature

```
alert http any any -> any any (msg:"HTTP user-agent list"; http.user_agent; to_sha256; dataset:isset,ua-sha256,type sha256, state /var/lib/suricata/datasets/seen-dns.lst, memcap 10mb, hashsize 1024; sid:123; rev:1;)
```

## Live update

Here is the important section.

```
dataset:isset,ua-sha256,type sha256, state /var/lib/suricata/datasets/seen-dns.lst
```

Note that rule starts with `isset` to verify existence of list element. You could also use `isnotset` to check for element to be absent and `set` to add a missing element to the list. Items can be added to the set manually via `dataset-add` unix socket command.

## Dataset rule

Suppose we have a list of spambot mail servers from threat intel feed, stored in some plaintext file. For example in `/var/lib/suricata/datasets/mailservers.lst`. Good PCAP to test it is [here](https://malware-traffic-analysis.net/2020/12/07/index.html). We can write a following rule that on its own does not do much.

```
alert dns any any -> any any (msg:"Spambot mailservers seen"; dns.query; dataset:isset,spambots, type string, state /var/lib/suricata/datasets/mailservers.lst, memcap 10mb, hashsize 10000; sid:123; rev:1;)
```

Note that:
* Name of the dataset is `spambots`;
* Dataset file location is in `/var/lib/suricata/datasets/mailservers.lst`
* We are limiting the memory usage and hastable size of this set to 10MB and 10000 elements respectively;
* Rule produces a new alert whenever someone does a DNS query to a domain that we have labeled as spambot;

## Adding elements

Adding a element, such as `mail.militaryrelocator.com` to this list requires us to base64 encode it when using `string` datatype.

```
echo -n mail.militaryrelocator.com | base64
```

Using `sha256` datatype requires hashing the added value instead.

```
echo -n mail.militaryrelocator.com | sha256sum
```

Note that calling `echo` would implicitly add a newline symbol to the string. While barely visible to human eye, it's nothing more than extra char to computer. No different from any other letter. And that would affect the base64 value of the string. Suricata does not add this newline, so base64 would differ. We use `echo -n` to avoid this issue.

We could append output of this command directly to `/var/lib/suricata/datasets/mailservers.lst` and then start Suricata. Or we could start Suricata (for example in unix-socket mode if working on offline PCAPs) and use `dataset-add` command to insert the element.

```
sudo suricatasc -c "dataset-add spambots string $(echo -n mail.militaryrelocator.com | base64)"
```

**Suricata must be shut down for it to store newly added datasets on disk!** Once you have done this, you can verify that added element is in persistence file.

```
grep `echo -n mail.militaryrelocator.com | base64` /var/lib/suricata/datasets/mailservers.lst
```

With little scripting, you can easily add a lot of elements to that set.

```
cat mailservers.txt | while read line ; do sudo suricatasc -c "dataset-add spambots string $(echo -n $line | base64)" ; done
```

## Setting new values in rules

Alternatively, we could simply generate a list of unique mail servers with following rules. Note that we are using `set` keyword to add new elements to hash table, whereas before we were using `isset` to check for element existence.

```
alert dns any any -> any any (msg:"New mailserver query seen"; dns.query; content: "mail"; startswith; dataset:set,new-mailservers, type string, state /var/lib/suricata/datasets/new-mailservers.lst, memcap 10mb, hashsize 10000; sid:123; rev:1;)
```

## Worked example — alert on bad domains (string dataset)

The `string` type is the workhorse: any sticky buffer can be checked against a list. Here we hook
`dns.query` to a list of known-bad domains, so **one** rule fires on a DNS lookup of **any** of them.

String entries are stored **base64-encoded** (see [Adding elements](#adding-elements)), so build the
list with `base64` — one encoded domain per line:

```
for d in malware-c2-test.example spambot-test.example ; do
  echo -n "$d" | base64
done | sudo tee /var/lib/suricata/datasets/bad-domains.lst
sudo chown suricata:suricata /var/lib/suricata/datasets/bad-domains.lst
```

One rule covers the whole list:

```
alert dns any any -> any any (msg:"DNS lookup of known-bad domain"; dns.query; dataset:isset,bad-domains,type string,load /var/lib/suricata/datasets/bad-domains.lst,memcap 10mb,hashsize 1024; sid:9000002; rev:1;)
```

Trigger it — any DNS query for one of the names works, it doesn't have to resolve:

```
dig @8.8.8.8 malware-c2-test.example
```

Each matching query produces an alert (verified on 8.0.5). Unlike the `type ip` IPv4 file loader, the
`string` loader behaves identically on 7.x and 8.x.

## IP datasets

Initial datasets only supported sticky buffers (rule *options*), so IP addresses — matched in the rule *header* — couldn't be used. Since Suricata 7 there are sticky buffers for IP matching (`ip.src` / `ip.dst`), so an address can be checked against a dataset.

* https://docs.suricata.io/en/latest/rules/ipaddr.html#ip-addresses-match

```
alert ip $HOME_NET any -> any any (msg:"Bad IP seen"; ip.dst; dataset:isset,bad-ip,type ip,load bad-ip.lst,hashsize 10000; sid:1; rev:1;)
```

Unlike the string type, IP addresses are written as plain text (no base64). `ip.dst` (or `ip.src`) picks which address to test.

Two limits worth knowing (both verified on 8.0.5):

* **Exact addresses only — no CIDR.** A dataset is a hash set of individual addresses; a network such as `10.0.0.0/24` is **rejected at load** (`invalid Ipv4/Ipv6 value`) and never matches. For subnet matching use the rule header (`alert ip ... -> [10.0.0.0/24] any ...`) or `iprep`, not a dataset.
* **Pick the type per address family.** Use **`type ipv4`** for IPv4 lists, and **`type ip`** (or `type ipv6`, both work) for IPv6 lists. The combined `type ip` is currently broken for IPv4 **file** loads on 8.0.x (see the caveat below), so don't use it for IPv4 lists.

### Worked example — one rule, a thousand IPs (Tor exit nodes)

This is the whole point of datasets: a **single** rule that fires when a host touches **any** address in a large, externally-maintained list — and you update the list without touching the rule. Tor publishes its exit nodes as a flat IP list (1200+ today):

```
curl -s https://check.torproject.org/torbulkexitlist -o /var/lib/suricata/datasets/tor-exits.lst
sudo chown suricata:suricata /var/lib/suricata/datasets/tor-exits.lst
```

One rule covers the entire set. The Tor list is all IPv4, so use **`type ipv4`** (see the 8.0.x
caveat below for why `type ip` won't load an IPv4 file):

```
alert ip $HOME_NET any -> any any (msg:"Outbound to Tor exit node"; ip.dst; dataset:isset,tor-exits,type ipv4,load /var/lib/suricata/datasets/tor-exits.lst,memcap 16mb,hashsize 8192; sid:9000001; rev:1;)
```

Refresh the list (cron the `curl`) and restart — no rule changes, no per-IP rule explosion.

> **⚠️ Suricata 8.0.x caveat (verified on 8.0.5).** The combined **`type ip`** **file** loader is
> currently **IPv6-only**: every line in a `load`/`state` file is parsed as IPv6, so **plain IPv4
> entries are dropped**. At runtime each IPv4 line logs `Warning: ... invalid Ipv6 value
> <dataset-name> in <file>` (note it prints the *dataset name*, not the offending address) and the
> entry is skipped — so an all-IPv4 list like `torbulkexitlist` loads **zero** entries under
> `type ip`. Under `suricata -T` the same condition is a **fatal error** (config test exits non-zero).
> The docs say `type ip` should accept "IPv6 or IPv4 address", and Suricata **7.0.15 loads and
> matches the identical IPv4 file fine**, so this is a **regression** in 8.0.x — distinct from the
> already-fixed socket-side [#7689](https://redmine.openinfosecfoundation.org/issues/7689).
> *Root cause:* the dataset file parser was rewritten C→Rust in 8.0 and lost the IPv4 fallback —
> v8 [`process_ipv6_set`](https://github.com/OISF/suricata/blob/suricata-8.0.5/rust/src/detect/datasets.rs#L238-L247)
> parses every line as IPv6 only, whereas v7
> [`ParseIpv6String`](https://github.com/OISF/suricata/blob/suricata-7.0.15/src/datasets.c#L248-L277)
> fell back to `inet_pton(AF_INET, …)` for colon-less (IPv4) lines.
>
> **Two file-backed workarounds, both verified on 8.0.5 (load *and* match):**
>
> 1. For an **all-IPv4** list, use **`type ipv4`** (as in the rule above) — it loads a plain-IPv4
>    file, `ip.dst`/`ip.src` matches IPv4 packets correctly, and a saved set (`state`) **round-trips
>    across a restart**. (`type ip` does *not*: it writes plain IPv4 on shutdown but rejects it on
>    reload, so a `type ip` IPv4 set silently loses every entry on restart.)
> 2. To keep using **`type ip`** (e.g. a mixed v4/v6 list), write each IPv4 entry as an
>    **IPv4-mapped IPv6** address — `::ffff:1.2.3.4`. That passes the IPv6 parser and still matches
>    plain-IPv4 packets. Convert the Tor list with:
>    ```
>    sed 's/^/::ffff:/' torbulkexitlist > tor-exits.lst   # then dataset:...,type ip,load tor-exits.lst
>    ```
>
> (Adding IPv4 over the unix socket — `dataset-add … ip 1.2.3.4` — also works but is **not persisted**
> across a restart, since the saved file hits the same broken loader on reload.)

## Tasks

Use PCAP files specified by the instructors.

* Write one single rule detecting default user-agents (exact matches on lowercase strings are fine);
    * Python;
    * Nikto;
    * Dirbuster;
    * Nmap;
    * Curl
* Create a `string` list of all unique **dns queries**, **http user-agents**, **http.uri**, **ja3 fingerprints** and **TLS certificate issuers**;
  * lists should be generated **without getting any alerts**;
  * Verify each list element with `base64 -d`;
* From those lists, select some interesting values and add them to new dataset;
  * Ensure that you get alerts when those elements are observed in PCAP or on wire;
* Write a script that generates a dataset called `ad-domain-blacklist` from [this hosts file](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts);
  * Enhance the prior solution to also add reputation value for each entry;
