# vagrant

 * https://docs.saltstack.com/en/latest/ref/modules/all/index.html
 * https://docs.saltstack.com/en/latest/ref/states/all/index.html
 * http://jinja.pocoo.org/docs/2.9/templates/
 * https://docs.saltstack.com/en/latest/topics/jinja/index.html
 * https://docs.saltstack.com/en/latest/topics/pillar/
 * https://docs.saltstack.com/en/latest/topics/grains/index.html

This repository is meant to be used as a local development environment. Easiest way to get started is to use virtualbox provider.

```
vagrant up
```

Vagrant environment will also deploy a dedicated saltmaster VM, in order to reflect realistic production setup. However, we do not pre-seed minion keys, allowing minion to generate new certificate requests upon each `vagrant up`. Therefore, developer must accept key manually within the saltmaster VM.

## accept keys on master

 * Note that minion config part is already handled by Vagrant

```
vagrant ssh saltmaster
sudo salt-key -L
sudo salt-key -A -y
```

Note that developer does not need superuser privileges to use salt execution modules as vagrant user. This is due to pre-configured ACL within salt-master config file. However, local system administration tasks (e.g. accepting certificate requests) still require elevation.

## test connectivity with minions

```
salt '*' test.ping
```

## pull client-side information from minions

```
salt '*' grains.ls
salt '*' grains.get os
```

## run any command on minion

```
salt '*' cmd.run 'ifconfig'
```


# States

Salt does configuration management, in addition to orchestration.

```
salt '*' state.apply <statename>
salt '*' state.highstate
```

## Point master to state and pillar dirs

```
vim /etc/salt/master
```
```
file_roots:
  base:
    - /vagrant/salt
    - /var/cache/salt/master/minions
pillar_roots:
  base:
    - /vagrant/pillar/
```
```
systemctl restart salt-master.service
```

## Create first state

```
vim /vagrant/salt/test.sls
```

```
common:
  file.managed:
    - name: /tmp/1

after:
  cmd.run:
    - name: echo after
    - onchanges:
      - file: /tmp/1
```

## add state to top file

* Otherwise code will not be applied
* base == environment (must be configured first in master config)
* `*` == apply on all minions
* `test` == filename from previous step
  * `/vagrant/salt/test/init.sls` would achieve the same result

```
vim /vagrant/salt/top.sls
```

```
base:
  '*':
    - test

```

## define server-side variables

* can be used like grains, but are defined on server
* are defined exactly like states
* are applied separately from states

```
vim /vagrant/pillar/suri.sls
```

```
suricata:
  homenets: "[192.168.0.0/16,10.0.0.0/8]"
  interface: ethX
```

## apply server-side variables

* different files can be applied using different criteria

```
base:
  'suricata-*':
    - suri
```
