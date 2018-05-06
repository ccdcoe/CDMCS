# multihost

  * The purpose of this environment is to create a multi-viewer, multi-cluster capture environment in classroom
  * By default, `vagrant up` will create a single box with reasonable amount of CPU and RAM (4 cores, 4 gigs)
  * Each student will be assigned a number and a cluster (in other words, sit next to people you want to cluster up with)
  * It will be up to each team to decide how their cluster is designed (i.e., who will do live capture, who will host [ES data nodes](/common/elastic/elastic.config.basic.md), etc)
  * However! Each student must be running a viewer and you must be able to access PCAPs from any node.
  * Before doing `vagrant up`, please define box public IP according to student number you received in class
  * Optionally, you can increase the number of nodes in Vagrantfile if you have enough RAM in laptop
  * We will decide on maximum number of hosts per student in class, though, as classroom IPv4 network range will be limited. 
  * Please don't make us debug IP conflicts. Pretty please. The setup will rely on Vagrant [public networks](https://www.vagrantup.com/docs/networking/public_network.html), so each student will be assigned N IPv4 addresses starting from their student number
  * Salt master-minion setup is optional, documentation on that can be found [here](/Suricata/vagrant/multihost/README.md)
  * Consider enabling saltmaster if you decide on multi-host vagrant setup
  * Once your cluster is up and running, each student must set up parliament (and maybe also multi-cluster in config.ini), thus bridging all the clusters together
  * tl;dr - set up multiple moloch clusters where each student is a small node, then create multi-cluster parliament setup. If time, wargames, more on salt, sending sessions from one cluster to another, [pcaps and more pcaps](http://malware-traffic-analysis.net/)
