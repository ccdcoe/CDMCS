# Prerequisites

This page lists some simple commands, code snippets and questions that attendees should understand before coming to class.

## Linux command line

* How to list running processes?
  * How to kill/terminate a process?
* Find all TCP and UDP listeners on Linux system.
* What is a difference between process and thread?
* How to redirect output of one program into input of another in Unix-like system?
* What is the purpose of `/var`, `/home`, `/bin`, `/mnt` and `/srv` directories in Linux filesystem?
  * What is the fundamental difference between `/srv`, `/mnt` and `/opt`?
* How to set an IP address to network interface from command line without editing any files or restarting any services?
* What is a regular expression?
* What is syslog?
  * Where are log files usually located on a Linux system?

### Know this stuff

  * [Linux file system hierarchy](http://www.tldp.org/LDP/Linux-Filesystem-Hierarchy/html/)
  * [Vim](https://www.vim.org/) or [Nano](https://www.nano-editor.org/). First one is preferred and used by teachers.
  * ["Predictable" network interface naming](https://www.freedesktop.org/wiki/Software/systemd/PredictableNetworkInterfaceNames/)
  * [tcpdump](https://www.tcpdump.org/manpages/tcpdump.1.html)

### Explain the following commands and scripts

```
FILE=/etc/apt/apt.conf.d/99force-ipv4
[[ -f $FILE ]] ||  echo 'Acquire::ForceIPv4 "true";' | sudo tee $FILE
```

```
for src in et/open ptresearch/attackdetection oisf/trafficid; do suricata-update list-enabled-sources | grep $src || suricata-update enable-source $src >> /vagrant/provision.log 2>&1 ; done
```

```
#!/bin/bash

if [[ ! -f /var/run/generator-2 ]]; then
  while : ; do curl -s https://www.facebook.com/ > /dev/null 2>&1 ; sleep 10 ; done & sleep 1; echo $! > /var/run/generator-1
  while : ; do curl -s http://testmyids.com > /dev/null 2>&1 ; sleep 10 ; done & sleep 1; echo $! > /var/run/generator-2
  while : ; do curl -s http://tumblr.com > /dev/null 2>&1 ; sleep 10 ; done & sleep 1; echo $! > /var/run/generator-3
fi
```

What is the difference between these two `echo` statements?
```
export myname="CDMCS"
echo "$myname"
echo '$myname'
```

## Scripting

### Explain the following commands and scripts

```
import json
def task(data={"foo":"bar"}):
    return json.dumps(data).encode(encoding="utf-8") + "\n".encode(encoding="utf8")
```

```
echo foo | python -c "import sys; print(sys.stdin.read())"
```

