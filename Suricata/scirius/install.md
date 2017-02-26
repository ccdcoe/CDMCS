# Scirius install on Debian | Ubuntu

see:

* https://github.com/StamusNetworks/scirius#installation-and-setup

```
SCIRIUS="scirius_1.1.99-1_amd64.deb"

[[ -f $SCIRIUS ]] ||wget  -q -4 http://dl.stamus-networks.com/scirius/trainings/$SCIRIUS

dpkg -i $SCIRIUS

```

----

Next -> [configuration](config.md)
