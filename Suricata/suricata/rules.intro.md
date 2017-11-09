# Rules

> Suricata alerting is rule-based. Commonly, rulesets are externally developed.

> You need to manage and update your rules every day!


## A quick look into what kind of rules we have

* How many rules do we have?


Remove all comments
```
grep -v '^ *#' emerging-all.rules
```

What actions?
```
grep -v '^ *#' emerging-all.rules | cut -s -d' ' -f1 | sort | uniq -c
```

What protocols?
```
grep -v '^ *#' emerging-all.rules | cut -s -d' ' -f2 | sort | uniq -c
grep -v '^ *#' emerging-all.rules | cut -s -d' ' -f2 | sort | uniq -c | sort -n
```

Any other fields to inspect?


More:

* http://suricata.readthedocs.io/en/latest/rules/intro.html
* https://rules.emergingthreats.net/open/
* https://www.proofpoint.com/us/daily-ruleset-update-summary

----
Tomorrow -> [Writing a rule](/Suricata/suricata/writing.first.rule.md)
