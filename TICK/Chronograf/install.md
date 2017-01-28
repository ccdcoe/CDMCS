# Installing Chronograf on Debian | Ubuntu

* https://github.com/influxdata/chronograf/blob/master/docs/INSTALLATION.md#chronograf-setup

```
#check influxdb running
curl "http://localhost:8086/query?q=show+databases"

# check kapacitor running
kapacitor list tasks

wget https://dl.influxdata.com/chronograf/nightlies/chronograf_nightly_amd64.deb
sudo dpkg -i chronograf_nightly_amd64.deb
service chronograf start

```

Chronograf by default listens port 8888

-----
-> Next [Generate Tick script](chronoGenerateTickScript.md)
