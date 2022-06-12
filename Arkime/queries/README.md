# Using the viewer

Arkime viewer already includes comprehensive documentation under `/help` url, aka *the owl logo*. This section only serves to provide some context and examples. **Please refer to official docs for up-to-date reference for field types, supported expressions, etc**.

See your `singlehost` VM Arkime installation for `/help`
 * http://192.168.10.11:8005/help

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

**On exercise Arkime data.**

 * Find plaintext http on port 443;
 * Filter for traffic that contains data;
 * Investigate time-series data per gamenet host;
 * Drill down to specific protocols;
 * Investigate traffic between workstations;
 * Filter only traffic for your team;

# API

[Arkime v3 API reference](https://arkime.com/apiv3)

As you soon discover, manual search does not really scale and interesting findings can be surprisingly difficult to reproduce. And all those fields, protocols, teams, subnets...if only we could *for loop* it somehow...

Viewer is nothing more than HTTP endpoint behind digest authentication that aggregates data from elastic. So, why not send HTTP GET requests for listing interesting stuff.

# Hunting trip

## Task

 * Your task is to group up and go on a hunting trip. 
  * The goal, if it can be called like that, is to investigate sessions and IP addresses to identify Red team servers, compromised hosts, strange traffic patterns and possible causes, to differentiate scoring and connectivity from malicious traffic, etc. 
  * **There are no right or wrong answers, no ground truth!!!** Only traffic that is interesting and noise. 
  * **Note down your findings and possible explanations**.
  * Present your approach and findings at the end!
  * You may be called to give a status update during work. Don't be afraid to say you are stuck - other teams may have ideas or suggestions to help you out.

Some ideas and suggestions for getting started:
 * No one query nor API call will give you the whole picture, you must pivot between queries.
  * Use API to your advantage for collectiong possible indicators, then investigate by hand. Write off sessions that are not interesting, collect new indicators from those that are. Rinse and repeat.
 * Start by looking for common indicators - script tags in user-agents and URL-s, mistyped domains, strange peaks of traffic, IDS alerts, well-known protocols on non-standard ports, non-standard protocol on standardized ports, etc. Then look at involved IP addresses. Anything coming from simulated internet? See what else has that IP doing.
 * IP addresses can be changed but may nevertheless exhibit common patterns, for example ja3 hashes, TLS certificate fingerprints, common URI patterns, cookies, etc.
 * Arkime lets you apply views and tag sessions. Use that! If something is not interesting, mark it as such and get rid of it. Whatever is left might be interesting.
 * So, you found one connection going to or coming from a CnC server...and then nothing. It may be initial compromise and interesting traffic is happening through some other IP or protocol. Are there any new streams that started exactly after that initial session?
 * What about traffic between targets and workstations? Any patterns or indicators for filtering out lateral movement?
 * Do not forget that you can also search from packets in Hunt tab. Just be sure to apply a strong expression beforehand. Let's not kill the capture server.
 * Have a cool idea for search but no idea how to do it in Arkime? Ask the instructurs, that's why we are here.
 * On that note, have a cool idea and making progress? Let us and other teams know. We can mark it down and help out everyone.
 * ...your suggestions go here...
