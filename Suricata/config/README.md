# Config

This section assumes familiarity with Suricata runmodes, CLI options and compilation.

 * https://suricata.readthedocs.io/en/latest/configuration/suricata-yaml.html#

Suricata YAML is where the real configuration resides. It is always implicitly loaded and student may have already seen failures if it's missing. Now let's dig deeper. Use `-c` to point Suricata toward config file. That way, you can copy default config and test changes in working env. Or you could do multiple config files for different use-cases!

```
suricata -c <config-dir>/suricata.yaml
```

Just as with rules, test configuration with `-T` flag and increase verbosity as needed.

```
suricata -c <config-dir>/suricata.yaml -T -vvv
```

`suricata.yaml` is fairly well documented with comments. You can also use `--dump-config` to verify configuration from Suricata binary.

```
suricata --dump-config
```

Them move on to important steps.

## Packet acquisition

Modern method for getting packets from kernel space to suricata is `af-packet`. Interface can be defined as command line flag.

```
suricata --af-packet=enp0s3 -S /vagrant/var/rules/suricata.rules  -l /home/vagrant/logs -D -vvv
```

A proper way would be to define interfaces in `suricata.yaml`. Note that `cluster-id` values should be unique. **Across all tools that use af-packet!**.

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

Then run suricata with empty `--af-packet` flag. That flag is still needed as suricata needs to know its runmode. But we no longer point it towards a specific interface in CLI. That will come from config file.

```
suricata --af-packet -S /vagrant/var/rules/suricata.rules  -l /home/vagrant/logs -D -vvv
```

## Home networks

Edit `suricata.yaml` with proper network information. You should see the following in the head of the file. **Do not forget IPv6**.

```
vars:
  # more specific is better for alert accuracy and performance
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    #HOME_NET: "[192.168.0.0/16]"
    #HOME_NET: "[10.0.0.0/8]"
    #HOME_NET: "[172.16.0.0/12]"
    #HOME_NET: "any"

    EXTERNAL_NET: "!$HOME_NET"
    #EXTERNAL_NET: "any"

    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
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
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
```

These variables are used in rules to indicate perimeter directionality. Following rule would not trigger if your internal network segments are not in `HOME_NET` definition.

```
#alert tcp $EXTERNAL_NET any -> $HOME_NET 143 (msg:"GPL IMAP login literal buffer overflow attempt"; flow:established,to_server; content:"LOGIN"; nocase; pcre:"/\sLOGIN\s[^\n]*?\s\{/smi"; byte_test:5,>,256,0,string,dec,relative; reference:bugtraq,6298; classtype:misc-attack; sid:2101993; rev:5; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
```

## Logging and EVE JSON

 * https://suricata.readthedocs.io/en/latest/output/eve/eve-json-output.html
 * https://suricata.readthedocs.io/en/latest/output/eve/eve-json-format.html
 * https://suricata.readthedocs.io/en/latest/output/eve/eve-json-examplesjq.html

When built with JSON support, `eve.json` should be in `default-log-dir`.

```
grep "default-log-dir" suricata.yaml
```

EVE can be configured under `outputs` as a list of `eve-log` elements. Note that `eve-log` can be called multiple times with different writers and log streams! For example, following config would separate `alert.json` from other protocol logs.

```
outputs:
  - eve-log:
      enabled: 'yes'
      filetype: regular
      filename: alert.json
      community-id: yes
      community-id-seed: 0
      types:
        - alert:
            payload: no
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            http-body: no
            http-body-printable: yes
            metadata: yes
            tagged-packets: no
  - eve-log:
      enabled: 'yes'
      filetype: regular
      filename: protocols.json
      types:
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - files:
            force-magic: no
        - drop:
            alerts: yes
        - smtp:
            extended: yes
        - dnp3
        - nfs
        - smb
        - tftp
        - ikev2
        - krb5
        - dhcp:
            enabled: yes
            extended: yes
        - ssh
        - flow
```

### tl; dr

In short, this is your typical to-do list in `suricata.yaml` after fresh install -

 * Home nets;
 * Default log directory;
 * eve.json output;
 * af-packet input;
 * rules;
    * update;
    * Rule directory;
    * rule file;
 * run suricata with `--af-packet` argument;

### Exercises

* Build suricata with VM uplink (+IPv6) as HOME_NET
* Set up [virtual replay](/Suricata/live) and configure it as second capture interface;
  * Use MTA data to verify it works!
* Make sure that af-packet uses zero-copy mode
* Configure ruleset profiling (it needs to be compiled into Suricata)
  * Profile `et/open` ruleset on that replay traffic
