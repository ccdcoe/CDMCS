# Basic usage and writing queries

  * For all documentation about Moloch query syntax and general usage, please refer to Owl on top left corner of viewer UI

## Filtering tasks

  * Write a query which filters all traffic that might contain plaintext HTTP connections
  * Combine that query with filter that shows all non-HTTP traffic on those ports
  * Write similar filters for TLS, SSH and DNS traffic
  * Filter out all traffic that does not contain any payload
  * Likewise, only look for traffic that reaches moloch maximum session size (10000 packets)
  * Write a query that filters out your team domain controllers 

## Usage

  * Draw timeline graphs for all subnets for your team
  * Write a filter that only shows HTTP payload sizes in timeline
  * Explore HTTP header values in SPI view
  * Explore IDS alerts in moloch
  * Find a plaintext HTTP session on port 443, download the pcap and explore the content in wireshark
