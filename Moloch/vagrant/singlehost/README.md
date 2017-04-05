# Moloch (& Suricata (&& EEK)) in single box

* **Moloch** is full packet capturing, indexing, and database system.
* MOLOCH is not IDS
* *WISE* is part of Moloch. Wise is helper service to check external knowledge before saving session index data.
* **Suricata** is IDS and NSM tool.
*  *EveBox* is a web based Suricata "eve log" event (including *alerts*) viewer and has [API to query alerts](http://evebox.readthedocs.io/en/latest/api.html#get-api-1-alerts).
* *ElasticSearch* is a search engine.



* WISE plugin **[source.suricata.js](source.suricata.js)** *"connects"* Moloch session to Suricata alert.


# Get it running on YOUR laptop, before you come to classroom

* Yes, you need to bring your own laptop!

* Yes, you need to get it up and running in your laptop!

A quick way to get a classroom||testing||development environment up and running is with **Vagrant**. You will need recent versions of [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org/) installed.

Install the latest versions of Vagrant and VirtualBox for your operating systems, and then run:

    vagrant status

If you get any error message, [fix them before creating any VM's](https://www.vagrantup.com/docs/virtualbox/common-issues.html).


To create and provision a new virtual machine :

    mkdir somedirnameyoulike
    cd dirnameyoujustcreated
    wget https://github.com/ccdcoe/CDMCS/blob/master/Moloch/vagrant/singlehost/installMolochSuricataEveboxKibana.sh
    wget https://github.com/ccdcoe/CDMCS/blob/master/Moloch/vagrant/singlehost/Vagrantfile
    vagrant up


Running `vagrant up` for the first time will run provisioning, which will:
- Download the [Ubuntu 16.04 base image](https://atlas.hashicorp.com/ubuntu/boxes/xenial64) <sup>[(1)](#mybox)</sup>, if there isn't already a copy on your machine
- Create a new VirtualBox virtual machine from that image
- Run the provisioning script ([installMolochSuricataEveboxKibana.sh](installMolochSuricataEveboxKibana.sh)) <sup>[(2)](#readitbeforeyouexecuteit)</sup>

The Vagrant box will automatically start after provisioning. It can be started in future with `vagrant up` from the *dirnameyoujustcreated* directory.

Once the Ubuntu virtual machine has booted, it will start Moloch (and Suricata and Evebox and Elasticsearch). You can then access your **Moloch viewer** at **http://192.168.10.11:8005**. By default, your development environment will have an admin account created for you to use - the username will be `admin` and the password will be `admin`.

To stop the server, simply run `vagrant halt`.

Should you need to access the virtual machine (for example, to manually fix something without restarting the box), run `vagrant ssh` from the *dirnameyoujustcreated* folder. You will now be logged in as the `ubuntu` user.

If your instance or Vagrant box are really not behaving, you can re-run the provisioning process. Stop the box with `vagrant halt`, and then run `vagrant destroy` - this will delete the virtual machine. You may then run `vagrant up` to create a new box, and re-run provisioning.

### Support/help

If you are confused, or having any issues with the above, join the Moloch Slack server (https://slackinvite.molo.ch/) or Suricata IRC channel (irc.freenode.net #suricata).
If you can not get it running properly, do not worry, day 0 is for helping you out.
If you can not get it running at all, do not worry, Tallinn is nice medieval city and has a good number of [tourist attractions](https://www.visittallinn.ee/eng/visitor/see-do/sightseeing) ;)

----

<sup><a name="mybox">(1)</a> :: Or build your own box, see [here](https://www.vagrantup.com/docs/boxes/base.html) </sup>

<sup><a name="readitbeforeyouexecuteit">(2)</a> :: Whenever you have to execute a shell script from the web, first open url in your web browser to make sure the script isn't malicious and is safe to run.</sup>
