# System requirements for the classroom training

  * Host OS: Linux or MacOS preferred, with Windows you are responsible for making vagrant and SSH work;
    * Please avoid nested virtualization (i.e, Virtualbox inside Linux inside VMware workstation on a Windows machine);
  * RAM: 16GB or more system memory;
  * Disk: Minimum 50GB of free disk space, 100GB or more recommended. SSD preferred;
  * Network: 
    * Ethernet port (RJ-45);
    * Ability to create a bridged public network for virtual machines;

# Moloch (& Suricata (&& EEK)) in single box

  * **[Moloch](http://molo.ch/)** is full packet capturing, indexing, and database system.
    * Moloch is not an IDS
  * Some other software is necessary:
    * **[WISE](https://github.com/aol/moloch/wiki/WISE#WISE__With_Intelligence_See_Everything)** is part of Moloch. Wise is helper service to check external knowledge before saving session index data.
    * **[ElasticSearch](https://www.elastic.co/guide/index.html)** is a search engine based on Lucene.
  * We will also have:
    * **[Suricata](https://suricata-ids.org/)** is a network threat detection engine.
    * **[Redis](https://redis.io/)** is a in-memory data structure storage and message broker. Good for sharing data between multiple applications.

# Instructions

A quick way to get a classroom||testing||development environment up and running is with **Vagrant**. You will need recent versions of [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org/) installed. Hyper-v setup is also supported, albeit with certain limitations.

  * [Read up on vagrant](/common/vagrant)
  * [Read up on docker](/common/docker)

Install the **latest versions** of Vagrant and VirtualBox for your operating systems, and then run:

```
vagrant global-status
```

Clone this repository and enter this directory:

```
git clone https://github.com/ccdcoe/CDMCS.git
cd CDMCS/Moloch/vagrant/singlehost
```

Verify that your environment is correct.

```
➜  singlehost git:(master) ✗ vagrant status 
Current machine states: 
 
moloch                    not created (virtualbox) 
 
The environment has not yet been created. Run `vagrant up` to 
create the environment. If a machine is not created, only the 
default provider will be shown. So if a provider is not listed, 
then the machine is not created for that environment. 
```

Then start the provisioning process.

```
vagrant up --provider virtualbox
```

Note the `--provider` key. Virtualbox will be the default when omitted. You need to specify another provider if you are not using virtualbox, such as `--provider hyperv`. Virtualbox and hyper-v are mutually exclusive. However, first read the `Vagrantfile` source to see if your hypervisor is supported.

Once the provisioning process finishes, make sure that you are able to access the VM via ssh.

```
vagrant ssh
uname -a
```

Make sure that you have private network connectivity to VM. On **host**, ping the private address `192.168.10.11`. Vagrant network config is not supported on hyper-v. Check the address manually.
