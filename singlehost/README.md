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
cd CDMCS/Moloch/singlehost
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

# FAQ

## Command X from provisioning script does not work / provisioning fails;

If it happens during classroom training, then it's a bug or connectivity issue. If it happens during prep period, then it's perfectly normal. Singlehost is an open-source software stack. New versions are released, old link stop working. New technologies emerge, sometimes at last minute. We are constantly improving the script to package more cool stuff. You cannot live on bleeding edge without cutting yourself every now and again.

## Do I need to get all of this up and running before coming to class?

Yes and no. We need to verify that basic tooling and environment is suitable for classroom, as it is a hands-on course and everything will be done inside Vagrant virtual machines. Thus, working virtualization with proper intra and inter host connectivity is critical. However, day 0 afternoon is dedicated to debugging these issues and on provisioning the singlehost, basically to get everyone on the same level. 

### Already provisioned everything before the class? 

Good job. You'll be bored on day0 and real work starts on day1. 

### You have not provisioned the singlehost but can virtualize with Vagrant? 

Perfect. You'll get to poke around singlehost on day0. 

### You cannot virtualize with Vagrant at all, or box network connectivity does not work? 

That sucks. You won't get anything out of this course if we can't hack it to work. Debugging these issues would detract our attention from actual classroom topics, so they should be resolved before we start working.

## So everything will be done on singlehost VM throuhout the course?

No. Every major topic will be covered in a dedicated Vagrant VM. Sometimes we assume that these VM-s can be linked together to conserve resources. That way you always have a fresh environment when learning a new topic, without having to build on single messy image.

## Wait, so what's the point of singlehost?

Singlehost is a packaged version of most topics covered throughout the course, and also as reference / proof-of-concept when developing the learning materials. In essence:

  * You get first taste of what is to come by being *shoved in the deep end* ASAP;
  * Then you learn how to build this stack throughout the week;
  * You can refer to singlehost provisioning script when working on classroom tasks, most solutions are already in the script;
  * You can take singlehost home afterwards, when you start building it for yourself;

## What, everything is already there? Why can't we just use the working stack throughout the week?

Because then you would not learn anything. Contrary to disturbingly popular opinion, you must understand how things work in order to properly defend your systems. Attacking and breaking things is orders of magnitude easier than building and defending your infrastructure. Our goal is not to teach you which button to push, but rather to increase the understanding about what that button does or weather that button even serves any purpose. Your systems back home may be vastly different and there is no *one size fits all* solution. No silver bullets.

## Could I do all the tasks on my host instead?

If you have a reasonably recent Linux host, sure, you *could*. But please don't. Entire curriculum is designed to be doable on disposable virtualized envoronments. **Keep your host clean**. Furthemore, Vagrant serves as a *reset button* in case you mess up. **And messing up is normal, even encouraged in the classroom**. It's how you learn. In other words `vagrant destroy && vagrant up` saves a lot of pointless debug time. Doing everything on dedicated virtual machines also teaches you how these systems interact on network level, as opposed to using localhost for everything.
