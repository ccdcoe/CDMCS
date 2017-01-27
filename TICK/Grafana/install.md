# Installing on Debian | Ubuntu

```
$ wget https://grafanarel.s3.amazonaws.com/builds/grafana_4.1.1-1484211277_amd64.deb
$ sudo apt-get install -y adduser libfontconfig
$ sudo dpkg -i grafana_4.1.1-1484211277_amd64.deb
$ sudo service grafana-server start
```

By defaul configuration file is located at */etc/grafana/grafana.ini*

By default Grafana will:  
 * log to */var/log/grafana*
 * use sqlite3 database located at */var/lib/grafana/grafana.db*
 * have initial username and password *admin*
 * listen to the port *3000*

-----

 -> next [Add data source](addDataSource.md)
