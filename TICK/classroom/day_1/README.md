# Day 1

* build one TICK component from source
 * set up disposable development enviroment (vagrant)
 * set up golang
* add one custom plugin to one TICK component
 * plugin templates
* install all configure all components
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

see
* https://golang.org/doc/install#install
* https://github.com/golang/go/wiki/Ubuntu
* http://golangcode.com/how-to-install-go-in-ubuntu-16-04/
* [go setup](/common/SetUpGoLang.md)


# plugin templates

* inputs
  * https://github.com/influxdata/telegraf/blob/master/plugins/inputs/EXAMPLE_README.md
  * https://github.com/influxdata/telegraf/blob/master/plugins/inputs/mock_Plugin.go
* outputs
* aggregators
* parsers
* processors
* serializers




# Adding a bind9 plugin to Telegraf

* https://github.com/influxdata/telegraf/tree/master/plugins/inputs
* https://raw.githubusercontent.com/markuskont/telegraf/master/plugins/inputs/bind9/bind9.go
