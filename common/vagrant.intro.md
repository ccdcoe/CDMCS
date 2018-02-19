# Vagrant

* https://github.com/mitchellh/vagrant#vagrant
* https://www.vagrantup.com/docs/why-vagrant/
* http://slides.com/hillar/vagrant#/

## Vagrant is :
* a tool for building complete development environments.
* is a tool for building and distributing development environments.
* an automation tool with a domain-specific language (DSL) that is used to automate the creation of VMs and VM environments.

## install:

* https://www.vagrantup.com/downloads.html

### Getting started:

* https://www.vagrantup.com/docs/getting-started/
* [prepare](https://www.vagrantup.com/docs/getting-started/project_setup.html)
* [up & ssh](https://www.vagrantup.com/docs/getting-started/up.html)
* [destroy](https://www.vagrantup.com/docs/getting-started/teardown.html)
* [automated provisioning](https://www.vagrantup.com/docs/getting-started/provisioning.html)
* [boxes](https://www.vagrantup.com/docs/getting-started/boxes.html)

## Basic usage

### install vagrant

```
apt-get install virtualbox

VAGRANT='2.0.2'
WGET_OPTS='-q -4'

wget $WGET_OPTS https://releases.hashicorp.com/vagrant/$VAGRANT/vagrant_$VAGRANT_x86_64.deb 
dpkg -i vagrant_$VAGRANT_x86_64.deb
```

### init first vm
```
cd $HOME
mkdir vagrant_getting_started
cd vagrant_getting_started
vagrant init ubuntu/xenial64
```

### run vm
```
vagrant status
vagrant up
```

### use ssh
```
vagrant ssh
```

### start over
```
vagrant destroy
vagrant status
vagrant up
```

### see all vms
```
vagrant global-status
```

### ssh manually
```
ssh -i .vagrant/machines/bridge/virtualbox/private_key vagrant@192.168.13.254
```
