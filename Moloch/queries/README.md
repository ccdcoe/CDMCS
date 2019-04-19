# Using the viewer

Moloch viewer already includes comprehensive documentation under `/help` url, aka *the owl logo*. This section only serves to provide some context and examples. **Please refer to official docs for up-to-date reference for field types, supported expressions, etc**.

See
 * http://192.168.10.11:8005/help
 * http://192.168.10.12:8005/help

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

Capture statistics. Vital for administration, especially in high-bandwidth environment. Not important for hunting.

### History

Query history for the user. Admin tab for auditing.

### Settings

Admin tab for various things. Like chaning the interface color...but still useful for hunting because cron queries can be configured here. So, peridic query and alert in the pocket. Yes please.

### Users

Admin tab but user limitations can be can be configured here. Like enabling hunt tab, allowing for search in email traffic, applying forced view limitations via query, etc.

## Tasks

On exercise data.

 * Find all sessions that are tagged by Suricata alert;
  * Filter only alerts with highest severity;
  * Split the view per signature, choose some that seem interesting and investigate the source and destination addresses;
 * Find plaintext http on port 443;
  * Filter for traffic that contains data;
 * Investigate time-series data per gamenet host;
  * Drill down to specific protocols;
 * Investigate traffic between workstations;
  * Filter only traffic for your team;

# API

 * https://github.com/aol/moloch/wiki/API

As you soon discover, manual search does not really scale and interesting findings can be surprisingly difficult to reproduce. And all those fields, protocols, teams, subnets...if only we could *for loop* it somehow...

Viewer is nothing more than HTTP endpoint behind digest authentication that aggregates data from elastic. So, why not send HTTP GET requests for listing interesting stuff.

## Bash Examples

List unique DNS records in time interval. Only search from dns sessions.

```
curl -u vagrant:vagrant --digest \
	--data-urlencode "startTime=$(date -d '04/16/2019 17:00:00' +"%s")" \
	--data-urlencode "stopTime=$(date -d '04/16/2019 18:00:00' +"%s")" \
	--data-urlencode "expression=protocols==dns" \
	--data-urlencode "exp=dns.host" \
	-GET "http://192.168.10.11:8005/unique.txt"
```

Get unique user agents for past two hours.

```
curl -u vagrant:vagrant --digest \
  --data-urlencode "date=2" \
	--data-urlencode "expression=protocols==http&&http.user-agent!=Mozilla*" \
	--data-urlencode "exp=http.user-agent" \
	-GET "http://192.168.10.11:8005/unique.txt"
```

Collect unique ja3 hashes from TLS connections in past 6 hours into a bash variable.

```
ua=$(curl -ss -u vagrant:vagrant --digest \
  --data-urlencode "date=6" \
	--data-urlencode "expression=protocols==tls" \
	--data-urlencode "exp=tls.ja3" \
	-GET "http://192.168.10.11:8005/unique.txt")
```

For each listed ja3 hash, run a query for all DNS connections directed at port 443 and list source IP addresses.

```
echo $ja3 | while read line ; do echo $line ; curl -ss -u vagrant:vagrant --digest \
  --data-urlencode "date=6" \
  --data-urlencode "expression=protocols==tls&&port.dst==443&&tls.ja3==$line" \
  --data-urlencode "exp=ip.src" \
  -GET "http://192.168.10.11:8005/unique.txt" ; done
```

List tcp connections between target workstations in exercise phase 1 that contain some data and are tagged by Suricata alert. Present at most 1000 connections in CSV format, while listing only protocol, source and destination addresses, alerting signature, [community ID](https://packages.zeek.org/packages/view/73967193-4fb7-11e8-88be-0a645a3f3086) of the connection, and affected team-zone combination.

```
curl -ss -u $USER:$PASS --digest \
  --data-urlencode "startTime=$(date -d '04/10/2019 06:00:00' +"%s")" \
  --data-urlencode "stopTime=$(date -d '04/10/2019 10:00:00' +"%s")"  \
  --data-urlencode "exp=ip.src" \
  --data-urlencode "expression=databytes>10&&workstation.iter.src==EXISTS\!&&workstation.iter.dst==EXISTS\!&&protocols!=udp&&suricata.signature==EXISTS\!" \
  --data-urlencode "fields=ipProtocol,srcIp,dstIp,suricata.signature,communityId,ls19.team_src,ls19.team_dst" \
  --data-urlencode "length=1000" \
  -GET http://$HOST:8005/sessions.csv
```

Gather unique community ID-s from suricata hourly alert json file.

```
cid=$(zcat ~/Data/ls19/alerts/2019.04.10.11.gz| jq .community_id | sort -h | uniq))
```

For each community ID in variable, execute a Moloch query to retreive all indexed sessions with that ID. Note that time range matches exactly the hourly interval of alert file. Searching from any other interval would be pointless.

```
echo $cid | while read line ; do echo $line ; curl -ss -u $USER:$PASS --digest \
	--data-urlencode "startTime=$(date -d '04/10/2019 11:00:00' +"%s")" \
	--data-urlencode "stopTime=$(date -d '04/10/2019 12:00:00' +"%s")" \
	--data-urlencode "expression=communityId==$line" \
	-GET http://$HOST:8005/sessions.csv ; done
```

## Python examples

 * See attached jupyter notebooks;

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
 * Moloch lets you apply views and tag sessions. Use that! If something is not interesting, mark it as such and get rid of it. Whatever is left might be interesting.
 * So, you found one connection going to or coming from a CnC server...and then nothing. It may be initial compromise and interesting traffic is happening through some other IP or protocol. Are there any new streams that started exactly after that initial session?
 * What about traffic between targets and workstations? Any patterns or indicators for filtering out lateral movement?
 * Do not forget that you can also search from packets in Hunt tab. Just be sure to apply a strong expression beforehand. Let's not kill the capture server.
 * Have a cool idea for search but no idea how to do it in Moloch? Ask the instructurs, that's why we are here.
 * On that note, have a cool idea and making progress? Let us and other teams know. We can mark it down and help out everyone.
 * ...your suggestions go here...
