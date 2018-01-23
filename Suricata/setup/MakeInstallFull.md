# Run 'make install-full' to install configuration and rules

```
root@secx:/home/student/oisf# make install-full
Making install in libhtp

...

install -d "/usr/local/etc/suricata/rules"
/usr/bin/wget -qO - https://rules.emergingthreats.net/open/suricata-3.0/emerging.rules.tar.gz | tar -x -z -C "/usr/local/etc/suricata/" -f -

You can now start suricata by running as root something like '/usr/local/bin/suricata -c /usr/local/etc/suricata//suricata.yaml -i eth0'.

If a library like libhtp.so is not found, you can run suricata with:
'LD_LIBRARY_PATH=/usr/local/lib /usr/local/bin/suricata -c /usr/local/etc/suricata//suricata.yaml -i eth0'.

While rules are installed now, it's highly recommended to use a rule manager for maintaining rules.
The two most common are Oinkmaster and Pulledpork. For a guide see:
https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Rule_Management_with_Oinkmaster

```
