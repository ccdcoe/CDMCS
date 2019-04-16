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

# Managing elastic
