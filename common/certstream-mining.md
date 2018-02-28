## Cert Transparency overview

https://www.certificate-transparency.org/

## An attempt with Naive Bayes and RF

https://github.com/sulliwan/mustmets

* Uses Google safebrowsing and various DNSBL-s to check domains for blacklists
* Takes a lexicon of "suspicious words"
* Converts the certstream to a binary bag of words per domain name
* Attempts to train classifiers on that data

## Actually working example

https://github.com/x0rz/phishing_catcher

* Uses a custom ruleset to calculate a score per domain

## Main problems

* There is actually very little data in the stream, mostly just the domain name which is interesting
* Very unbalanced dataset (proportion of phishing/malware domains to legit domains is very low)
* Future problem: Let's Encrypt will issue wildcard certs, which reduce the amount of meaningful data even further
