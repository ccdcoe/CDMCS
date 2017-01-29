# Kapacitor configuration

* https://docs.influxdata.com/kapacitor/v1.2/introduction/installation/#configuration
* https://github.com/influxdata/kapacitor/blob/master/etc/kapacitor/kapacitor.conf

Kapacitor can also provide an example config for you using `kapacitord config`

To generate a new configuration file, run ` kapacitord config > kapacitor.generated.conf `

### retention-policy
Default retention-policy, if a write is made to Kapacitor and
it does not have a retention policy associated with it,
then the retention policy will be set to this value

```
default-retention-policy = "TODO"
```

------
-> Next [TICKscript](TICKscript.md)
