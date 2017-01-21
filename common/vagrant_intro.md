# Vagrant

### Vagrant is :
* a tool for building complete development environments.
* is a tool for building and distributing development environments.
* an automation tool with a domain-specific language (DSL) that is used to automate the creation of VMs and VM environments.
* ...

### see:
* https://github.com/mitchellh/vagrant#vagrant
* https://www.vagrantup.com/docs/why-vagrant/
* http://slides.com/hillar/vagrant#/


### install:

* https://www.vagrantup.com/downloads.html

### [start:](https://www.vagrantup.com/docs/getting-started/)

1. [prepare](https://www.vagrantup.com/docs/getting-started/project_setup.html)
1. [up & ssh](https://www.vagrantup.com/docs/getting-started/up.html)
1. [destroy](https://www.vagrantup.com/docs/getting-started/teardown.html)

* [automated provisioning](https://www.vagrantup.com/docs/getting-started/provisioning.html)
* [boxes](https://www.vagrantup.com/docs/getting-started/boxes.html)

---

```

# install vagrant
$ wget -q -4 https://releases.hashicorp.com/vagrant/1.9.1/vagrant_1.9.1_x86_64.deb
$ dpkg -i vagrant_1.9.1_x86_64.deb

# init first vm
$ cd $HOME
$ mkdir vagrant_getting_started
$ cd vagrant_getting_started
$ vagrant init ubuntu/xenial64

# run vm
$ vagrant status
$ vagrant up

# use ssh
$ vagrant ssh

# start over
$ vagrant destroy
$ vagrant status
$ vagrant up

```
