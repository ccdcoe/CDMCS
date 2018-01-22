# Exercise - writing a basic rule

* Generate a pcap file that contains http connecitons to following links
  * https://www.facebook.com
  * http://sysadminnid.tumblr.com/
  * http://syssadminnid.tumblr.com/
* Verify 3 connections with wireshark
* Write a rule that triggers an alert whenever someone visits [this site](http://sysadminnid.tumblr.com/)
* Modify this rule to only fire on established responses
* Find the term "Nagios pisaraid ei usu" from established responses
* Use proper hexadecimal encoding to match special bytes and ensure that rule fires for both "sysadminnid" and "SysAdminnid"
