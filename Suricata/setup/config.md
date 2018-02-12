# Suricata configuration

see:
* https://suricata.readthedocs.io/en/latest/configuration/index.html
* https://github.com/inliniac/suricata/blob/master/src/conf-yaml-loader.c


> If a configuration option is not specified in  the configuration file, Suricata uses its internal default configuration.


## Conf test

```
suricata -T -vvv
```

## Show active config parameters

```
suricata --dump-config
```

## See only active configuration
suricata.yaml is like a documentation in itself. See the file without comments.
```
grep -v -E '^\s*#' /etc/suricata/suricata.yaml
# remove empty lines as well
grep -v -E '^\s*#' /etc/suricata/suricata.yaml | grep -v '^$'
sed -i -e 's/#.*$//' -e '/^\s*$/d' /etc/suricata/suricata.yaml
```

## Example HOME_NET and other vars

```
vars:
  address-groups:
    HOME_NET: "[198.18.0.0/22,2a07:1181:140::0/44,100.64.0.0/22,2a07:1181:120::0/64,100.64.134.0/24,2a07:1181:121::0/64,10.242.4.0/24,2a07:1181:130:3604::0/64,10.242.5.0/24,2a07:1181:130:3605::0/64,10.242.6.0/24,2a07:1181:130:3606::0/64,10.242.7.0/24,2a07:1181:130:3607::0/64]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
```

## online capture

```
af-packet:
  - interface: enp0s3
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: enp0s8
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
```

----

Next -> [Rules](/Suricata/rules)
