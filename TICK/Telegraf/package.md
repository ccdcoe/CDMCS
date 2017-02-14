# Making telegraf package

* Run *make package*
* start fixing the problems

```
apt-get install python ruby ruby-dev ruby-ffi build-essential
gem install fpm
cd /opt/go/src/github.com/influxdata/telegraf
make package
```
