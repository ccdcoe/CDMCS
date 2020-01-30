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

Please install the latest version from vagrant providers. Package from debian/ubuntu package repos will be out of date and bad things may happen.

```
VAGRANT='<LATEST>'
WGET_OPTS='-q -4'

wget $WGET_OPTS https://releases.hashicorp.com/vagrant/$VAGRANT/vagrant_$VAGRANT_x86_64.deb 
dpkg -i vagrant_$VAGRANT_x86_64.deb
```

## Getting started

* https://www.vagrantup.com/docs/getting-started/
* [prepare](https://www.vagrantup.com/docs/getting-started/project_setup.html)
* [up & ssh](https://www.vagrantup.com/docs/getting-started/up.html)
* [destroy](https://www.vagrantup.com/docs/getting-started/teardown.html)
* [automated provisioning](https://www.vagrantup.com/docs/getting-started/provisioning.html)
* [boxes](https://www.vagrantup.com/docs/getting-started/boxes.html)

Vagrant is a ruby wrapper/library which allows virtual machines to be automatically deployed for development. Deployment parameters would be stored in local `Vagrantfile`. Provisioning scripts and configuration management tools can be invoked upon first `vagrant up` or subsequent `vagrant provision` commands to automatically deploy and configure software inside the virtual machine.

```
$SHELL = <<SCRIPT
apt-get update && apt-get install -y git htop vim build-essential
SCRIPT

Vagrant.configure(2) do |config|
  config.vm.define 'CDMCS' do |box|
    box.vm.box = "ubuntu/bionic64"
    box.vm.hostname = 'CDMCS'
    box.vm.synced_folder ".", "/vagrant", disabled: false
    box.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--memory", "2048"]
      vb.customize ["modifyvm", :id, "--cpus", "2"]
    end
    config.vm.provision "shell", inline: $SHELL
  end
end
```

This example configures a single Ubuntu 18.04 virtual machine with 2GB ram, 2 CPU cores and sandboxed static network address `192.168.10.11`. Inline script will automatically install whatever packages the user needs.

## init first vm

Most vagrant commands rely upon local `Vagrantfile`. A minimal environment can be created using `vagrant init` command with desired base image as final argument. That box can be a custom image from local system, or alternatively a public box can be pulled from repository.

```
cd $HOME
mkdir vagrant_getting_started
cd vagrant_getting_started
vagrant init ubuntu/bionic64
```

## run vm

Following commands will check if local vagrant machines are running and then start any stopped machine.

```
vagrant status
vagrant up
```

### SSH to virtual machine

It is possible to SSH into virtual machines by using vagrant wrapper commands.

```
vagrant ssh
```

Note that vagrant is meant for development and thus SSH access must be preconfigured from box provider. SSH keys are packaged into the box itself. System is designed for ease of use not security. Prior command is roughly equvelant to this regular openssh-client command.

```
ssh -i .vagrant/machines/bridge/virtualbox/private_key vagrant@192.168.13.254
```

Common practice is to create a regular user `vagrant` with password `vagrant`. That user has passwordless sudo privilege to the system. But actual user name and default password is up to box author.

## start over

Sometimes you will mess up your box while developing and it is going to be easier to destroy everything and start from scratch. Do not be afraid of doing that, this is why Vagrant was created in the first place. Just make sure you update any deployment scripts with any progress you do not wish to lose.

```
vagrant destroy
vagrant status
vagrant up
```

A non-interactive alias to make this process faster would look like this.

```
alias whatever='vagrant destroy -f && vagrant up'
```

## see all vms

You have to be located in the folder where Vagrant environment was initiated. However, it is possible to find all initiated vagrant environments regardless where you are located in file system.

```
vagrant global-status
```

## multi-vm environment

See following examples (from year 2018 materials) on how to create more complex multi-vm environments:

  * [Moloch two host setup with salt master](https://github.com/ccdcoe/CDMCS/blob/2018/Moloch/vagrant/multihost/Vagrantfile)
  * [Suricata two host setup with salt master](https://github.com/ccdcoe/CDMCS/blob/2018/Suricata/vagrant/multihost/Vagrantfile)

Note that individual boxes can be programmed explicitly or created by looping over a data structure. Vagrant is a ruby library after all, so use scripting power as needed.

## Vagrant file server

By default the local working directory is mapped to `/vagrant` inside the VM. Thus, files can be shared between host and guest, or between guests in multi-vm environment. But any folder can be mapped.

```
  box.vm.synced_folder "../", "/srv/uponelevel", disabled: false
```

Several sync drivers are supported, such as virtualbox guest additions, rsync or NFS. Note that some base boxes do not have virtualbox additions installed, sometimes due to licencing issues. Rsync simple copies files between host and guest and does not keep them up to date in real time. NFS requires server to be installed on host. Furthermore, vagrant user must have permissions to modify `/etc/exports` file.

## Alternative providers

Virtualbox is the default hypervisor used by Vagrant. However, alternative hypervisors can be used, such as hyper-v, libvirt, or even cloud providers like azure. Configuring things like CPU core count and memory amount is usually provider specific and has to be defined as such in the same file.

```
Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu1604"
  config.vm.provider :virtualbox do |vb|
    vb.customize ["modifyvm", :id, "--memory", "2048"]
    vb.customize ["modifyvm", :id, "--cpus", "2"]
  end
  config.vm.provider "libvirt" do |v|
    v.memory = 4096
    v.cpus = 2
    v.machine_type = "q35"
  end
end
```

Different providers may have different features and operate differently. For example, libvirt provider allows alternative virtual hardware customization options and starts up multi-vm environments asynchronously. However, it is not packaged with Vagrant and should be installed as plugin and updated manually.

```
vagrant up --provider virtualbox
vagrant up --provider libvirt
```
