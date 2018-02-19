# Vagrant

* https://github.com/mitchellh/vagrant#vagrant
* https://www.vagrantup.com/docs/why-vagrant/
* http://slides.com/hillar/vagrant#/

## Vagrant is
* a tool for building complete development environments.
* is a tool for building and distributing development environments.
* an automation tool with a domain-specific language (DSL) that is used to automate the creation of VMs and VM environments.

## Install

* https://www.vagrantup.com/downloads.html

### Getting started

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

### SSH to virtual machine

It is possible to SSH into virtual machines by using vagrant wrapper commands.

```
vagrant ssh
```

Prior command is roughly equvelant to this regular openssh-client command.
```
ssh -i .vagrant/machines/bridge/virtualbox/private_key vagrant@192.168.13.254
```

### start over

Sometimes you will mess up your box while developing and it is going to be easier to destroy everyting and start from scratch. Do not be afraid of doing that, this is why Vagrant was created in the first place.

```
vagrant destroy
vagrant status
vagrant up
```

### see all vms

You have to be located in the folder where Vagrant environment was initiated. However, it is possible to find all initiated vagrant environments regardless where you are located in file system.

```
vagrant global-status
```

