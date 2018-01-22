# Exercise - writing a basic rule

* Generate a pcap file that contains http connecitons to following links
  * https://www.facebook.com
  * http://sysadminnid.tumblr.com/
  * http://syssadminnid.tumblr.com/
* Verify 3 connections with wireshark
* Write a rule that triggers an alert whenever someone visits [this site](http://sysadminnid.tumblr.com/)
* Modify this rule to only fire once per session

## helpers

 * http://suricata.readthedocs.io/en/latest/rules/http-keywords.html
 * http://suricata.readthedocs.io/en/latest/rules/payload-keywords.html
