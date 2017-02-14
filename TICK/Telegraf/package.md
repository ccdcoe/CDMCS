# Making telegraf package

* navigate to $GOPATH/src/github.com/influxdata/telegraf
* Run *make package*
* start fixing the problems one by one
* Note, that by default the *make package* will try to upload the packages to AWS. Either take the appropriate cmdline from Makefile or edit the makefile.

In a nutshell you will need
```
apt-get install python ruby ruby-dev build-essential rpm
gem install fpm
# Note, that by default the *make package* will try to upload the packages to AWS. Either take the appropriate cmdline from Makefile or edit the makefile.
# Edit the platform/arch etc. according to your needs.
cd $GOPATH/src/github.com/influxdata/telegraf/
./scripts/build.py --package --platform=linux --arch=amd64
ls build/
```
