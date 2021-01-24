# Rule writing

* https://suricata.readthedocs.io/en/latest/rules/index.html

This section **does not** assume any knowledge about Suricata YAML configuration. However, the student should be familiar with:
* Using Suricata with CLI flags (`-S`, `-l`, `-r`, `--af-packet=$IFACE`);
* Parsing offline PCAP files / simple traffic replay;
* Rule file, loading that rule file with `-S`;
* Exploring `eve.json` using `jq`;

Let's reiterate.
* Rules are organized per *rule files*, usually they have suffix `.rules`
* Suricata can load many rule files from *rules directory*
* Easiest way to test is still to create a single rule file and load that exclusively with `-S` flag
* `-S` (uppercase) does exclusive load of a single rule file
* `-s` (lowercase) appends rule file to others in configuration, in other words, not exclusive
* Rule is comprised of `actions`, `header` and `rule-options`
* action is mostly `alert`, unless running Suricata as inline IPS
* header is a 5-tuple with direction indicator (6-tuple really): (`protocol` `src_ip` `src_port` `direction` `dest_ip` `dest_port`)
    * direction could be `>` (forward), `<` (backward) or `<>` (bilateral)
    * never really used in practice, mostly the 5-tuple network elements is just flipped
    * meaning rules can trigger in either direction!
* rule-options is where the real match logic lies
* **Each rule must have unique `sid` option**

## Test cases

Firstly, you need PCAP files with positive and negative test cases. You can use `tcpdump` to generate both of them. But sites like [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) are also a great resource.

## Boilerplate

Following boilerplate is bare minimum to get a working rule that will alert on every TCP session. Put it into a rule file, like `custom.rules` (name is up to you, just sync it).

```
alert tcp any any -> any any (msg:"BOILERPLATE"; sid:1000000000; rev:1;)
```

Don't debug in runtime. Do it offline with proper tools! Suricata provides `-T` flag to run in testing mode. That way it will parse rule file and exit, reporting any errors along the way.

```
./bin/suricata -S custom.rules -T
```

If all goes well, you should just see a exit message. To see more information about internals, for example how many rules were loaded, then use `-v`, `-vv` or `-vvv` to raise logging verbosity. Following command should be enough to see how many rules were loaded into the engine.

```
./bin/suricata -S custom.rules -T -v
```

Then use Suricata to parse a sample PCAP.

```
mkdir logs-boilerplate
suricata -r $PCAP -S custom.rules -l ./logs-boilerplate/
```

And look into alerts.

```
cat logs-boilerplate/eve.json | jq 'select(.event_type=="alert")'
```

You should have alert for every TCP session, how much very useful.

## Using keywords

As mentioned, Suricata supports a lot of keywords. Those are documented [here](https://suricata.readthedocs.io/en/latest/rules/index.html). But you can also ask Suricata.

```
suricata --list-keywords
```

For example, suppose I need a quick list of all HTTP keywords.

```
suricata --list-keywords | grep http
```

Now suppose I noticed a this `http.url` that clearly indicates a malware download. Courtesy of MTA dataset.

```
/wp-content/plugins/ultimate-tinymce/includes/artifact209.exe
```

We can easily modify our boilerplate with `content` to match on malicious exe file.

```
alert tcp any any -> any any (sid:10000001; msg: "CDMCS: Malware IOC"; content: "artifact209.exe")
```

But this is a very bad rule. As it matches on entire TCP payload. So it could trigger on any protocol provided that string is preset. Seen some powershell rules trigger because a textual log containing `powershell` string was backed up via SMB. But not only is it **prone to false positives**, it also **kills performance**. How to improve it?

* Firstly, change protocol from `tcp` to `http`. That's where we see the IOC;
* Secondly, looking into parsed `http` events gives us access to HTTP sticky buffers, so we can direct our lookup explicitly to `http.uri` buffer;
* Finally, IOC file name is at the very end of the URL, so why not look for it there;

To get information about the  `http.uri` keyword we can use the following command (or just search in the doc):

```
$ suricata --list-keywords=http.uri
= http.uri =
Description: sticky buffer to match specifically and only on the normalized HTTP URI buffer
Features: No option,sticky buffer
Documentation: https://suricata.readthedocs.io/en/latest/rules/http-keywords.html#http-uri-and-http-uri-raw
```

So ` http.uri` is as expected a sticky buffer and we can build our alert as follow:

```
alert http any any -> any any (sid:10000001; msg: "CDMCS: Malware IOC"; http.uri; content: "artifact209.exe"; endswith;)
```

This lookup would be done on every single `http.uri`. But `content` can be called multiple times. Suricata evaluates buffers sequentially, so it's always a good idea to put lighter matches first. For example, this rule should only be fully evaluated on `GET` requests. `http.method` buffer is a great help here. And, we can try to avoid any weird edge cases by also verifying that flow is properly established, and that it's a request directed toward server. Not only does it make the rule stronger, **it also makes it much faster as nonapplicable sessions are discarded as soon as possible**.

```
alert http any any -> any any (sid:10000000; msg: "This is a simple rule"; flow:to_server,established; http.method; content: "GET"; http.uri; content: "artifact209.exe"; endswith;)
```

To check if our rule is not badly written, we can use suricata engine analysis:

```
suricata --engine-analysis -S ~/tmp/basic.rules -l /tmp/
```

In `/tmp/rules_analysis.txt` we have the following text:

```
-------------------------------------------------------------------
Date: 23/1/2021 -- 21:07:53
-------------------------------------------------------------------
== Sid: 10000000 ==
alert http any any -> any any (sid:10000000; msg: "This is a simple rule"; flow:to_server,established; http.method; content: "GET"; http.uri; content: "artifact209.exe"; endswith;)
    Rule matches on http uri buffer.
    Rule matches on http method buffer.
    App layer protocol is http.
    Rule contains 0 content options, 2 http content options, 0 pcre options, and 0 pcre options with http modifiers.
    Fast Pattern "artifact209.exe" on "http request uri (http_uri)" buffer.
    No warnings for this rule.
```

Signature seems valid as text ends up with `No warnings`. If we lookk at the other options, we can see a really interesting line:

```
    Fast Pattern "artifact209.exe" on "http request uri (http_uri)" buffer.
```

Which means that multi pattern matching is done on the `http.uri` buffer.

## Flowbits

* https://suricata.readthedocs.io/en/latest/rules/flow-keywords.html#flowbits

Consider following [case](https://malware-traffic-analysis.net/2021/01/05/index.html)

Suppose we have following malware IOC-s in `http.url`.

```
"/BB732D8A.moe"
"/6730A78E.moe"
"/BFA5A83F.moe"
```

What if we want to write rules that checks for **download** of these IOC-s. So, that not only was URL requested, but it also a positive response that triggered download. We could try this:

```
alert http any any -> any any (msg: "IOC match"; sid: 99; http.method; content: "GET"; http.stat_code; content: "200"; http.uri; content: "BFA5A83F.moe";)
```

But it's not going to work.

```
14/1/2021 -- 15:46:03 - <Error> - [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - rule 99 mixes keywords with conflicting directions
```

That's because `GET` method is part of HTTP request and status code `200` is part of response. So, they are part of different packets. That's a problem.

Solution is to use **flowbits**. As the name implies, Suricata is able to set specific bits per flow, which is useful for simple event correlation. That solves our problem, as one rule set a bit value whenever a IOC is seen in request. Flowbit `set` command is used to mark the flow with `malware.IOC` flag. Note that we don't want this side to generate a alert yet, so `noalert` flowbit keyword is also used.

```
alert http any any -> any any (msg: "SET - 1"; sid: 101; http.uri; content: "BB732D8A.moe"; endswith; flowbits: set,malware.IOC; flowbits: noalert;)
alert http any any -> any any (msg: "SET - 2"; sid: 102; http.uri; content: "6730A78E.moe"; endswith; flowbits: set,malware.IOC; flowbits: noalert;)
alert http any any -> any any (msg: "SET - 3"; sid: 103; http.uri; content: "BFA5A83F.moe"; endswith; flowbits: set,malware.IOC; flowbits: noalert;)
```

Having defined our IOC pattern rules for HTTP request, we can then proceed with writing a rule that checks for `malware.IOC` flag with `isset` keyword. However, it only alerts if HTTP response code was `200`.

```
alert http any any -> any any (msg: "CHECK - 0"; sid: 100; http.stat_code; content: "200"; flowbits: isset,malware.IOC;)
```

Then run Suricata and check for alerts in `eve.json`, you should see only alerts from signature `100`. And each EVE record alert should also show `malware.IOC` tag.

## Tasks

* Write rules detecting default user-agents, but only if response code from server was 200 (OK);
    * Python;
    * Nikto;
    * Dirbuster;
    * Nmap;
    * Curl
* Inspect MTA case `2020-03-12-infection-traffic.pcap`;
    * Generate eve.json and inspect events;
    * Find the malicious file download;
* Write a rule that triggers when that file is downloaded;
    * mind flow direction;
    * set up prefilter;
    * match on malicious file name;
* Enhance the rule to only trigger if response was HTTP 301 or 200;
* Identify stage 2 download domain and write a IOC rule;
    * likewise, make sure that metch is as specific as possible;
* Where is the CnC server?
