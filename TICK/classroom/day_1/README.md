# Day 1

* build one TICK component from source
 * set up disposable development enviroment (vagrant + golang)
* add one custom plugin to one TICK component
 * plugin templates
* install all and configure all components
  * [Telegraf](/TICK/Telegraf/README.md)
  * [InfluxDB](/TICK/InfluxDB/README.md)
  * [Chronograf](/TICK/Chronograf/README.md)
  * [Kapacitor](/TICK/Kapacitor/README.md)
  * [Alerta](/TICK/Alerta/README.md)
  * [Grafana](/TICK/Grafana/README.md)


----

# development environment

## vagrant

see
* [vagrant setup](/common/vagrant_intro.md)

## go

There is golang in default Ubuntu repositories, but it is not up to date.

See:
* https://golang.org/doc/install#install
* https://github.com/golang/go/wiki/Ubuntu
* http://golangcode.com/how-to-install-go-in-ubuntu-16-04/
* [go setup](/common/SetUpGoLang.md)

Is go ready to go?
[go hello](/common/GoHello.md)


# telegraf

## build from source

see

* https://github.com/influxdata/telegraf#from-source


### plugin templates

* inputs
  * https://github.com/influxdata/telegraf/blob/master/plugins/inputs/EXAMPLE_README.md
  * https://github.com/influxdata/telegraf/blob/master/plugins/inputs/mock_Plugin.go
* outputs
* aggregators
* parsers
* processors
* serializers




## Adding a bind9 plugin to Telegraf

* https://github.com/influxdata/telegraf/tree/master/plugins/inputs
* https://raw.githubusercontent.com/ccdcoe/CDMCS/master/TICK/classroom/day_1/bind9.go
* https://raw.githubusercontent.com/markuskont/telegraf/master/plugins/inputs/bind9/bind9.go

```
sudo apt-get install bind9
```
```
sudo bash -c "cat >/etc/bind/named.conf.options" <<'EOF'
options {
        directory "/var/cache/bind";

        // If there is a firewall between you and nameservers you want
        // to talk to, you may need to fix the firewall to allow multiple
        // ports to talk.  See http://www.kb.cert.org/vuls/id/800113

        // If your ISP provided one or more IP addresses for stable
        // nameservers, you probably want to use them as forwarders.
        // Uncomment the following block, and insert the addresses replacing
        // the all-0's placeholder.

        forwarders {
             8.8.8.8;
        };

        //========================================================================
        // If BIND logs error messages about the root key being expired,
        // you will need to update your keys.  See https://www.isc.org/bind-keys
        //========================================================================
        dnssec-validation auto;

        auth-nxdomain no;    # conform to RFC1035
        listen-on-v6 { any; };
        statistics-file "/var/cache/bind/named.stats";
};
EOF
```
```
service bind9 restart
```
```
sudo rndc stats
```
```
cat /var/cache/bind/named.stats
```
```
+++ Statistics Dump +++ (1486822840)
++ Incoming Requests ++
++ Incoming Queries ++
++ Outgoing Queries ++
[View: default]
                   2 NS
                   2 DNSKEY
[View: _bind]
++ Name Server Statistics ++
++ Zone Maintenance Statistics ++
```
```
sudo bash -c "cat >/etc/bind/named.conf.local" <<'EOF'
statistics-channels {
        inet 127.0.0.1 port 8080 allow { 127.0.0.1; };
};
EOF
```
```
curl -XGET localhost:8080
```
