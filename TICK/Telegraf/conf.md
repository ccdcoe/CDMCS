# Telegraf configuration

* configuration file from package is /etc/telegraf/telegraf.conf
* see https://docs.influxdata.com/telegraf/v1.2/administration/configuration/

#### Create a configuration file with default input and output plugins.

```
telegraf -sample-config > telegraf.conf

```

#### Create a configuration file with specific inputs and outputs

```
telegraf -sample-config -input-filter <pluginname>[:<pluginname>] -output-filter <outputname>[:<outputname>] > telegraf.conf

```
### Configuration sections

* Global Tags
* Agent
* Input
* Output

-------
-> Next [output](output.md)
