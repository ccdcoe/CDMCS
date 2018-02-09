# exercises

* Adapt the HTTP lua logging example from Suricata documentation (link in [README](README.md))
* Write a simple lua script that maintains a counter of seen IPv4 and IPv6 packets. Statistics should be printed to console upon closing Suricata
  * Modify this script to also maintain per-port statistics for well-known ports (1-1023)
* Write a lua script that maintains an in-memory list on previously seen TLS certificates, log all new certificates to a separate file
