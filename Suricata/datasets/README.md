# Datasets

* https://suricata.readthedocs.io/en/latest/rules/datasets.html

IDS rules have historically been rather static and self-contained entities. Threat detection, however, requires us to be dynamic and flexible. Consider [sslbl ja3 blacklist](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules) as an example. Each black or whitelisted hash needs to be separate rule with distinct ID. We could use PCRE with alternation, but that would kill our IDS performance. Best way to get around this limitation has been to generate those rules. While there is nothing wrong with this approach, it is still a hack around design limitations. Furthermore, entire ruleset needs to be reloaded if entries are added or removed from this list. 

`Datasets` is a new experimental (as of writing this readme) feature for eliminating this limitation. Any sticky buffer can be hooked to a list of base64 strings, md5, or sha256 hashes. `Datarep` is the same thing, but each entry can also be assigned a score. You can then define a threshold inside a rule, so it would trigger if reputation is above or below a numeric value.

## Basic usage

`Dataset` can be created in `suricata.yaml` and then invoked in a rule.

```
datasets:
  ua-sha256:
    type: sha256
    state: /var/lib/suricata/useragents-sha256.lst
```

```
alert http any any -> any any (msg:"HTTP user-agent list"; http.user-agent; to_sha256; dataset:isset,ua-sha256; sid:123; rev:1;)
```

Alternatively, the rule could be rewritten to contain all needed params. Modifying `suricata.yaml` would not be needed in that case.

```
alert http any any -> any any (msg:"HTTP user-agent list"; http.user-agent; to_sha256; dataset:isset,ua-sha256,type sha256, state /vagrant/seen-dns.lst; sid:123; rev:1;)
```

Note that rule starts with `isset` to verify existence of list element. You could also use `isnotset` to check for element to be absent and `set` to add a missing element to the list. Items can be added to the set manually via `dataset-add` unix socket command.

## Tasks

Use pcap files provided specified by the instructors. Vagrant VM traffic is too boring.

* Create a `string` list of all unique **dns queries**, **http user-agents**, **http.uri**, **ja3 fingerprints** and **TLS certificate issuers**;
  * lists should be generated **without getting any alerts**;
  * Enhance the prior solution to only add items to a list if certain criteria is met (instructors will provide this criteria in classroom);
  * Verify each list element with `base64 -d`;
* Write a script that generates a dataset called `ad-domain-blacklist` from [this hosts file](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts);
  * Enhance the prior solution to also add reputation value for each entry;
