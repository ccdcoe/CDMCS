# Before you come to class, you need to get moloch running on YOUR laptop

* Yes, you need to bring your own laptop!
* Yes, you need to get it up and running in your laptop!
* See instructions below

## System requirements for the classroom training
* Host OS: Linux or MacOS preferred, with Windows you are responsible for making vagrant and SSH work;
* RAM: 16GB or more system memory;
* Disk: Minimum 50GB of free disk space, 100GB or more recommended. SSD preferred;
* Network: Ethernet port (RJ-45).

# Arkime (& Suricata (&& EEK)) in single box

* **[Arkime](http://molo.ch/)** is full packet capturing, indexing, and database system.
  * Arkime is not an IDS
* Some other software is necessary:
  * **[WISE](https://github.com/aol/moloch/wiki/WISE#WISE__With_Intelligence_See_Everything)** is part of Arkime. Wise is helper service to check external knowledge before saving session index data.
  * **[ElasticSearch](/commoni/elastic/)** is a search engine based on Lucene.
* We will also have:
  * **[Suricata](https://suricata-ids.org/)** is a network threat detection engine.
  * **[Redis](https://redis.io/)** is a in-memory data structure storage and message broker. Good for sharing data between multiple applications.

### Suricata and Arkime

* Singlehost setup **[environment](/Arkime/vagrant/singlehost)** - full vagrant environment that includes moloch capture, viewer, backend document storage, threat intelligence and IDS tagging
* Old WISE plugin **[source.suricata.js](/Arkime/vagrant/singlehost/old/source.suricata.js)** *"connects"* Arkime session to Suricata alert. Consider as proof-of-concept only as this method does not handle production load
* New tagger script **[tagger.py](/Arkime/vagrant/singlehost/tagger.py)** *"queries"* Arkime for sessions that match suricata alert tuple (common source and destination). Assigns tags upon match.

# Instructions
A quick way to get a classroom||testing||development environment up and running is with **Vagrant**. You will need recent versions of [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org/) installed.

Install the latest versions of Vagrant and VirtualBox for your operating systems, and then run:

    vagrant status

If you get any error message, [fix them before creating any VMs](https://www.vagrantup.com/docs/virtualbox/common-issues.html).

Starting from VirtualBox v6.1.28 it is only allowed to provision VMs belonging to the 192.168.56.0/24 network range. To disable network range control (for both IPv4 and IPv6), add the following line to `/etc/vbox/networks.conf`. You have to create the file and directory if it does not exist yet.:

    * 0.0.0.0/0 ::/0

To create and provision a new empty virtual machine:

    mkdir something
    cd something
    vagrant box add ubuntu/jammy64
    wget https://raw.githubusercontent.com/ccdcoe/CDMCS/master/singlehost/Vagrantfile
    wget https://raw.githubusercontent.com/ccdcoe/CDMCS/master/singlehost/provision.sh
    vagrant up

Running `vagrant up` for the first time will run provisioning, which will:
- Download the [Ubuntu 22.04 base image](https://app.vagrantup.com/ubuntu/boxes/jammy64)<sup>[(1)](#mybox)</sup>, if there is not a copy on your machine already.
- Create a new VirtualBox virtual machine from that image
- Run the provisioning script ([provision.sh](/Arkime/vagrant/singlehost/provision.sh)) <sup>[(2)](#readitbeforeyouexecuteit)</sup>

The Vagrant box will automatically start after provisioning. It can be started in future with `vagrant up` from the *dirnameyoujustcreated* directory.

Once the Ubuntu virtual machine has booted, it will start Arkime (and Suricata and Evebox and Elasticsearch). You can then access your **Arkime viewer** at **http://192.168.10.11:8005**. By default, your development environment will have an admin account created for you to use - the username will be `admin` and the password will be `admin`. Here, at the prompt, you can try with `vagrant:vagrant`.

To connect to the server via SSH, simply run `vagrant ssh`. If you are running Windows (without ssh on your PATH), this might not work. Please fix it or find alternative means of connecting to your box via SSH.

To stop the server, simply run `vagrant halt`.

Should you need to access the virtual machine (for example, to manually fix something without restarting the box), run `vagrant ssh` from the *dirnameyoujustcreated* folder. You will now be logged in as the `ubuntu` user.

If your instance or Vagrant box are really not behaving, you can re-run the provisioning process. Stop the box with `vagrant halt`, and then run `vagrant destroy` - this will delete the virtual machine. You may then run `vagrant up` to create a new box, and re-run provisioning.


## Support/help

* If you are confused, or having any issues with the above, join the Arkime Slack server (https://slackinvite.molo.ch/) or Suricata IRC channel (irc.freenode.net #suricata).

* If you can not get it running properly, do not worry, day 0 is for helping you out.

* If you can not get it running at all, do not worry, Tallinn is nice medieval city and has a good number of [tourist attractions](https://www.visittallinn.ee/eng/visitor/see-do/sightseeing) ;)

----

<sup><a name="mybox">(1)</a> :: Or build your own box, see [here](https://www.vagrantup.com/docs/boxes/base.html) </sup>

<sup><a name="readitbeforeyouexecuteit">(2)</a> :: Whenever you have to execute a shell script from the web, first open url in your web browser to make sure the script is not malicious and is safe to run.</sup>
