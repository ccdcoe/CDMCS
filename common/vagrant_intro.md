# Vagrant

Vagrant is :
* a tool for building complete development environments.
* is a tool for building and distributing development environments.
* an automation tool with a domain-specific language (DSL) that is used to automate the creation of VMs and VM environments.
* ...

see:
* https://github.com/mitchellh/vagrant#vagrant
* https://www.vagrantup.com/docs/why-vagrant/
* http://slides.com/hillar/vagrant#/

start:
1. https://www.vagrantup.com/docs/getting-started/
1. https://www.vagrantup.com/docs/getting-started/project_setup.html
1. https://www.vagrantup.com/docs/getting-started/boxes.html
1. https://www.vagrantup.com/docs/getting-started/up.html
1. https://www.vagrantup.com/docs/getting-started/teardown.html
1. https://www.vagrantup.com/docs/getting-started/provisioning.html

---

```

# install vagrant
$ wget -q -4 https://releases.hashicorp.com/vagrant/1.9.1/vagrant_1.9.1_x86_64.deb
$ dpkg -i vagrant_1.9.1_x86_64.deb

# init first vm
$ cd $HOME
$ mkdir vagrant_getting_started
$ cd vagrant_getting_started
$ vagrant init ubuntu/trusty64

# run vm
$ vagrant up

# use ssh
$ vagrant ssh

# start over
$ vagrant destroy
$ vagrant up

```
