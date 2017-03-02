# load pcaps

see
 * https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Interacting_via_Unix_Socket
 * https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Multi_Tenancy
 * https://home.regit.org/2012/09/a-new-unix-command-mode-in-suricata/
 * https://www.networktotal.com

## Configuration

```
grep 'unix-command' -B5 -A2 /etc/suricata/suricata.yaml
```

```
suricata --help | grep unix
```

## For loop is easy?

```
for pcap in `find /pcapdir -type f -name '*.pcap'` ; do
	echo "I am doing stuff with $pcap"
done
```

## Using existing tool to interact with socket

```
suricatasc --help
```
