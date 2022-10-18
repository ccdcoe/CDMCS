# Datasets

* https://suricata.readthedocs.io/en/latest/rules/datasets.html

IDS rules have historically been rather static and self-contained entities. Threat detection, however, requires us to be dynamic and flexible. Consider [sslbl ja3 blacklist](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules) as an example. Each black or whitelisted hash needs to be separate rule with distinct ID. We could use PCRE with alternation, but that would kill our IDS performance. Best way to get around this limitation has been to generate those rules. While there is nothing wrong with this approach, it is still a hack around design limitations. Furthermore, entire ruleset needs to be reloaded if entries are added or removed from this list. 

`Datasets` is a new (ish) feature for eliminating this limitation. Any sticky buffer can be hooked to a list of base64 strings, md5, or sha256 hashes. `Datarep` is the same thing, but each entry can also be assigned a score. You can then define a threshold inside a rule, so it would trigger if reputation is above or below a numeric value.

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
alert http any any -> any any (msg:"HTTP user-agent list"; http.user_agent; to_sha256; dataset:isset,ua-sha256,type sha256, state /vagrant/seen-dns.lst; sid:123; rev:1;)
```

## Basic usage with Suricata 6.0.x

All parameters can be set in the signature

```
alert http any any -> any any (msg:"HTTP user-agent list"; http.user_agent; to_sha256; dataset:isset,ua-sha256,type sha256, state /vagrant/seen-dns.lst, memcap 10mb, hashsize 1024; sid:123; rev:1;)
```

## Live update

Here is the important section.

```
dataset:isset,ua-sha256,type sha256, state /vagrant/seen-dns.lst
```

Note that rule starts with `isset` to verify existence of list element. You could also use `isnotset` to check for element to be absent and `set` to add a missing element to the list. Items can be added to the set manually via `dataset-add` unix socket command.

## Dataset rule

Suppose we have a list of spambot mail servers from threat intel feed, stored in some plaintext file. For example in `/tmp/mailservers.lst`. Good PCAP to test it is [here](https://malware-traffic-analysis.net/2020/12/07/index.html). We can write a following rule that on its own does not do much.

```
alert dns any any -> any any (msg:"Spambot mailservers seen"; dns.query; dataset:isset,spambots, type string, state /tmp/mailservers.lst, memcap 10mb, hashsize 10000; sid:123; rev:1;)
```

Note that:
* Name of the dataset is `spambots`;
* Dataset file location is in `/tmp/mailservers.lst`
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

We could append output of this command directly to `/tmp/mailservers.lst` and then start Suricata. Or we could start Suricata (for example in unix-socket mode if working on offline PCAPs) and use `dataset-add` command to insert the element.

```
./bin/suricatasc -c "dataset-add spambots string $(echo -n mail.militaryrelocator.com | base64)"
```

**Suricata must be shut down for it to store newly added datasets on disk!** Once you have done this, you can verify that added element is in persistence file.

```
grep `echo -n mail.militaryrelocator.com | base64` /tmp/mailservers.lst
```

With little scripting, you can easily add a lot of elements to that set.

```
cat mailservers.txt | while read line ; do ./bin/suricatasc -c "dataset-add spambots string $(echo -n $line | base64)" ; done
```

## Setting new values in rules

Alternatively, we could simply generate a list of unique mail servers with following rules. Note that we are using `set` keyword to add new elements to hash table, whereas before we were using `isset` to check for element existence.

```
alert dns any any -> any any (msg:"New mailserver query seen"; dns.query; content: "mail"; startswith; dataset:set,new-mailservers, type string, state /tmp/new-mailservers.lst, memcap 10mb, hashsize 10000; sid:123; rev:1;)
```

## Tasks

Use PCAP files specified by the instructors.

* Write rules detecting default user-agents (exact matches on lowercase strings are fine);
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
