# Moloch & Suricata (in single box)

* **Moloch** is full packet capturing, indexing, and database system.
 * MOLOCH is not IDS
 * WISE is helper service to check external knowledge before saving session index data
* **Suricata** is checking traffic against described know threats indicators (rules) and creates and logs alert if match is found
 * Suricata is IDS (and NSM tool).
 *  EveBox is a web based Suricata "eve log" event, including alerts, viewer
  * Evebox has API to query alerts

* WISE plugin **[source.suricata.js](source.suricata.js)** *"connects"* Moloch session to Suricata alert.

# Get it running before you come to classroom

A quick way to get a classroom||testing||development environment up and running is with **Vagrant**. You will need recent versions of [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org/) installed.

Install the latest versions of Vagrant and VirtualBox for your operating systems, and then run:

    vagrant status

To create and provision a new virtual machine :

    mkdir somedirnameyoulike
    cd dirnameyoujustcreated
    wget https://github.com/ccdcoe/CDMCS/blob/master/Moloch/vagrant/singlehost/installMolochSuricataEveboxKibana.sh
    wget https://github.com/ccdcoe/CDMCS/blob/master/Moloch/vagrant/singlehost/Vagrantfile
    vagrant up


Running `vagrant up` for the first time will run provisioning, which will:
- Download the Ubuntu 16.04 base image, if there isn't already a copy on your machine
- Create a new VirtualBox virtual machine from that image
- Run the provisioning script (installMolochSuricataEveboxKibana.sh)

The Vagrant box will automatically start after provisioning. It can be started in future with `vagrant up` from the dirnameyoujustcreated directory.

Once the Ubuntu virtual machine has booted, it will start Moloch (and Suricata and Evebox and Elasticsearch). You can then access your *site* at http://192.168.10.11:8005 . By default, your development environment will have an admin account created for you to use - the username will be `admin` and the password will be `admin`.

To stop the server, simply run `vagrant halt`.

Should you need to access the virtual machine (for example, to manually fix something without restarting the box), run `vagrant ssh` from the *dirnameyoujustcreated* folder. You will now be logged in as the `ubuntu` user.

If your instance or Vagrant box are really not behaving, you can re-run the provisioning process. Stop the box with `vagrant halt`, and then run `vagrant destroy` - this will delete the virtual machine. You may then run `vagrant up` to create a new box, and re-run provisioning.

### Support/help

If you are confused, or having any issues with the above, join the Moloch Slack server (https://slackinvite.molo.ch/) or Suricata IRC channel (irc.freenode.net #suricata ).
