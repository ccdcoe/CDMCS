# Instructions for setting up the environment locally

Note, these instructions are for running a local instance of the tools in a VM. In the classroom, VMs have been prepared for you so you do not need to set this up before coming to class. But you can... :)


## System requirements for running these tools locally
* CPU: Modern 64-bit CPU, Apple Silicon has not been tested and is likely not supported.
* RAM: 16GB or more system memory;
* Disk: Minimum 50GB of free disk space, 100GB or more recommended. SSD preferred;
* Privileges: Root or Administrator privileges on the host OS.



# As a preparation, try to run Arkime (& Suricata (&& others)) in a single box

* Singlehost setup - full vagrant environment that includes Arkime capture, viewer, backend document storage, threat intelligence and IDS tagging

* **[Arkime](https://arkime.com/)** is full packet capturing, indexing, and searching system.
  * Arkime is not an IDS
* Some other software is necessary:
  * **[WISE](https://arkime.com/wise)** is part of Arkime. Wise is helper service to check external knowledge before saving session index data.
  * **[ElasticSearch](/common/elastic/)** is a search engine based on Lucene.
* We will also have:
  * **[Suricata](https://suricata.io/)** is a network threat detection engine.
  * **[Redis](https://redis.io/)** is a in-memory data structure storage and message broker. Good for sharing data between multiple applications.


### Instructions

A quick way to get a classroom-like||testing||development environment up and running is with **Vagrant**. You will need recent versions of [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org/) installed.

*NB! Vagrant v2.2.19 repository installation has a known issue with Ubuntu 22.04 LTS host system. Meanwhile, you can just use the fixed Linux binary download (also version v2.2.19) at the bottom of the [Vagrant Downloads page](https://www.vagrantup.com/downloads).*

Install the latest versions of Vagrant and VirtualBox for your operating systems, and then run:

    vagrant status

If you get any error message, [fix them before creating any VMs](https://www.vagrantup.com/docs/virtualbox/common-issues.html).

Starting from VirtualBox v6.1.28 it is only allowed to provision VMs belonging to the 192.168.56.0/24 network range. To disable network range control (for both IPv4 and IPv6), add the following line to `/etc/vbox/networks.conf`. You have to create the file and directory if it does not exist yet.:

    * 0.0.0.0/0 ::/0

You should be able to run these following commands as a regular (non-root) user.

To create and provision a the `singlehost` virtual machine:

    mkdir something
    cd something
    vagrant box add ubuntu/jammy64
    wget https://raw.githubusercontent.com/ccdcoe/CDMCS/master/singlehost/Vagrantfile
    wget https://raw.githubusercontent.com/ccdcoe/CDMCS/master/singlehost/provision.sh
    vagrant up

Running `vagrant up` for the first time will run provisioning, which will:
- Download the Ubuntu LTS base image if there is not a copy on your machine already.
- Create a new VirtualBox virtual machine from that image
- Run the provisioning script [provision.sh](https://raw.githubusercontent.com/ccdcoe/CDMCS/master/singlehost/provision.sh) <sup>[(2)](#readitbeforeyouexecuteit)</sup>

The Vagrant box will automatically start after provisioning. It can be started in future with `vagrant up` from the *dirnameyoujustcreated* directory.

Once the Ubuntu virtual machine has booted, it will start Arkime (and Suricata and Evebox and Elasticsearch). You can then access your **Arkime viewer** at **http://192.168.10.11:8005**. By default, your development environment will have an admin account created for you to use - the username will be `admin` and the password will be `admin`. Here, at the prompt, you can try with `vagrant:vagrant`.

To connect to the server via SSH, simply run `vagrant ssh`. If you are running Windows (without ssh on your PATH), this might not work. Please fix it or find alternative means of connecting to your box via SSH.

To stop the server VM, simply run `vagrant halt`.
To delete/destroy the server VM, simply run `vagrant destroy`.

Should you need to access the virtual machine (for example, to manually fix something without restarting the box), run `vagrant ssh` from the *dirnameyoujustcreated* folder. You will now be logged in as the `ubuntu` user.

## Troubleshooting
If your instance or Vagrant box are really not behaving, you can re-run the provisioning process. Stop the box with `vagrant halt`, and then run `vagrant destroy` - this will delete the virtual machine. You may then run `vagrant up` to create a new box, and re-run provisioning.

Remember, managing specific Vagrant VMs is couple to the directory of the `Vagrantfile`. So the current working directory (CWD) of your terminal should be 


## Support/help

* If you are confused, or having any issues with the above, join the Arkime Slack server (https://slackinvite.arkime.com/) or Suricata IRC channel (irc.freenode.net #suricata).

----

<sup><a name="mybox">(1)</a> :: Or build your own box, see [here](https://www.vagrantup.com/docs/boxes/base.html) </sup>

<sup><a name="readitbeforeyouexecuteit">(2)</a> :: Whenever you have to execute a shell script from the web, first open url in your web browser to make sure the script is not malicious and is safe to run.</sup>
