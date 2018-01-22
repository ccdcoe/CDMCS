# Writing Rule

> Do not write rules, buy from professionals !

 * http://suricata.readthedocs.io/en/latest/rules/intro.html
 * https://github.com/ccdcoe/CDMCS/blob/master/Suricata/vagrant/singlehost/provision-dalton.sh

## basic rule template
```
alert tcp any any -> any any (msg:"testing"; classtype:bad-unknown; sid:990001; rev:1;)
```

# more useful example
```
alert tcp any any -> any 443 (msg:"SURICATA Port 443 but not SSL/TLS"; app-layer-protocol:!tls; threshold: type limit, track by_src, seconds 180, count 1; classtype:bad-unknown;  sid:990002;)
```

A rule consists of the following:
* action
* header
* rule-options

### Action

* alert - This is the action we want to perform on the rule

* pass - This can be compared to “ACCEPT” in iptables, in that if the packet matches this rule it’ll be accepted through.
* drop - The packet doesn’t get processed any further down the chain and the sender isn’t notified. This is akin to the “DROP” target in iptables, where it will silently remove the packet from the network stack.
* reject - This acts the same as drop but will also notify the sender that the packet has been removed from the stack.

### Header

* First keyword: protocol with protocol recognition
* Second part: IP params includin variable

### Rule options

* content matching
* meta data
* threshold configuration

----
Next -> [Exercises](rules.exercises.md)
