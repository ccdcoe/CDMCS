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

sadly there is no configfile (yet?)


```
root@TICKAG:~# ps aux | grep chrono
chronog+  2421  0.5  0.8 308468 18432 ?        Ssl  22:39   0:04 /usr/bin/chronograf --host 0.0.0.0 --port 8888 -b /var/lib/chronograf/chronograf-v1.db -c /usr/share/chronograf/canned

root@TICKAG:~# chronograf -v
2017/01/28 22:52:37 Chronograf 1.2.0~n201701280835 (git: 2dbddaf84a03514471ac02d112bf4d63953bdfcf)

root@TICKAG:~# chronograf --help
Usage:
  chronograf [OPTIONS]

Options for Chronograf

Application Options:
      --host=                                                  the IP to listen on (default: 0.0.0.0) [$HOST]
      --port=                                                  the port to listen on for insecure connections, defaults to a random value
                                                               (default: 8888) [$PORT]
  -d, --develop                                                Run server in develop mode.
  -b, --bolt-path=                                             Full path to boltDB file (/var/lib/chronograf/chronograf-v1.db) (default:
                                                               chronograf-v1.db) [$BOLT_PATH]
  -c, --canned-path=                                           Path to directory of pre-canned application layouts
                                                               (/usr/share/chronograf/canned) (default: canned) [$CANNED_PATH]
  -t, --token-secret=                                          Secret to sign tokens [$TOKEN_SECRET]
  -i, --github-client-id=                                      Github Client ID for OAuth 2 support [$GH_CLIENT_ID]
  -s, --github-client-secret=                                  Github Client Secret for OAuth 2 support [$GH_CLIENT_SECRET]
  -o, --github-organization=                                   Github organization user is required to have active membership [$GH_ORGS]
  -r, --reporting-disabled                                     Disable reporting of usage stats (os,arch,version,cluster_id,uptime) once every
                                                               24hr [$REPORTING_DISABLED]
  -l, --log-level=choice[debug|info|warn|error|fatal|panic]    Set the logging level (default: info) [$LOG_LEVEL]
  -v, --version                                                Show Chronograf version info
      --basepath=                                              A URL path prefix under which all chronograf routes will be mounted

Help Options:
  -h, --help                                                   Show this help message


```

-----
-> Next [Using Chronograf](usingChronograf.md)
