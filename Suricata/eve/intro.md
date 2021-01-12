# Extensible Event Format (EVE)

## Background

* Suricata is not just for signatures
* At least, not any more
* Parsing entire payload is expensive
* Better to nail down specific fields
* Solution - per protocol parsers
  * HTTP
  * TLS
  * SMTP
  * ... and the list goes on
* Side effect - why not log extracted fields?
  
## EVE
  
* JavaScript Object Notation (JSON)
* key-value pairs
* enriched metadata

## Hands-on

* ...