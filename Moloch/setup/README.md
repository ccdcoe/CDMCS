# Build

See
* https://raw.githubusercontent.com/aol/moloch/master/easybutton-build.sh

While dep/rpm install is preferred these days, sometimes a custom build can save the day. A stable build may have unfixed bugs or might be missing critical functionality (missing parsers, etc). Furthermore, understanding how something is built will help you debug it in the future, regardless of how you deploy it in production.

## General build concepts

Moloch follows a standard *configure, make, make install*...in principle. It is actually comprised of multiple modules written in C and NodeJS (with additional scripting in Perl). Packaged `easybutton-build.sh` script essentially covers *configure* and *make* steps of this process, while *make install* does exactly that for components written in C and also builds NodeJS modules via *npm install*.

Note that Moloch attempts to bundle most dependencies as static libraries enclosed in project and deployment directories. That includes NodeJS and Npm (Node package manager), which must be present and and executable in *PATH* in order to deoploy the parts written in node. This can lead to a lot of confusion for those uninitiated to software deployment. One of the cleaner ways of dealing with this problem is to simply add Moloch binaries folder to the *PATH* environment variable.

```
export PATH=$PATH:/data/moloch/bin
```

Please adjust `/data/moloch` prefix accordingly. **It is up to you where Moloch is built and deployed**. Environment variables must also be explicitly present in all scripts and terminals that wish to invoke any binaries in PATH. Adding this line to `$HOME/.profile` or `$HOME/.bashrc` (or `.zshrc` if you are a hipster) will ensure that these binaries are always present for logged in terminal users, but not for headless init/systemd services.

If you wish to start the build process from scratch, then use `make clean`. If build process fails, then **read the logs**. Failure reasons are usually writted to stderr and mostly fall into these categories -

 * A missing binary due to dependency not installed;
 * A missing execution path;
 * Insufficient privileges to write to a folder.

Common issues with nodejs are:
 * Too new NodeJS installed from tarball. Version 8.x is supported at the time of writing this tutorial, with moloch 10.x planned for Moloch 2. Node develops fast. Too fast for most projects to keep up with newer releases. Moloch needs libraries that perform well and thus many modules might even be written in C++ and have not yet been updated to be compatible with newer V8 engine API;
 * Too old NodeJS installed from debian repositories. Libraries and language versions in *"stable"* LTS distributions are often ancient by the standards of bleeding edge NSM tools;
 * Wrong node package installed from repository. *Node* package in Ubuntu is not actually *nodejs*. **Use the nodejs bundled with moloch**, not anything installed on the system;
 * Nodejs, like vagrant and git, is meant to be executed in the project directory. In other words, if you want to execute `viewer.js`, you have to be located in the `viewer` directory.

Ensure that you have correct `node` and `npm` in path.

```
which node
which npm
node -v
npm -v
```

Capture issues:
 * Executing capture if pcap directory is missing or not readable will result in core dump over empty pointer!

 Finally, **keep you build and install directories separate!!!** Do not install moloch into the same folder where you cloned the code!

## Components

 * https://github.com/aol/moloch/wiki/Architecture#single-host

### Capture

Tcpdump-like tool written in C. Responsible for capturing packets from wire or reading from pcap file. Parses the sessions, writes raw packets into pcap files on disk and flushes indexed session data into elasticsearch. Optionally may ask for threat intelligence from WISE for various fields, such as IP, domain, md5, ja3, etc. Requires database but can be run independently from viewer. May require wise.

### Viewer

NodeJS frontent for querying and visualizing the sessions. Defaults to port `8005`. Indexed session and protocol data is read from elasticsearch while allowing sessions to also be opened. Opened sessions are are actually reconstructed from raw packets on disk as packet offsets are kept along the indexed data in elasticsearch. Requires database but may run independently from capture. May require wise. Can communicate with remote viewers to read pcaps from other capture hosts.

### Elasticsearch database

Stores indexed session data, field types, viewer users, pcap file locations on disk and individual packet offsets in each pcap file. Session data does not require pcap files to exist, but session payload can not be opened if capture files are missing or not readable by viewer. Does not depend on anything other than meta indices such as *fields*, *sequences*, etc. *Sessions2* indices are stored in timestamped sequences with configurable pattern, such as hourly, daily, weekly, etc.

### Pcap files

Raw packet capture files stored on disk. May be created by any tool that is able to write proper pcap format, but must be indexed by capture. Can be rotated separately from elasticsearch indices.

### WISE

*With intelligence see everything* is a NodeJS API for enriching sessions with custom fields or threat intelligence. For example, ip or domain lookups can be made against blacklist databases, asset names can be attached to make searching more simple, etc. Allows intelligence to be queried by anyone, not just moloch. May depend on custom field types in main config file. Moloch-capture submits sessions to wise in bulk prior to flushing to database.

### Parliament

NodeJS api for bridging multiple moloch clusters.

## Get the source

```
git clone https://github.com/aol/moloch.git /home/vagrant/build/moloch
cd /home/vagrant/build/moloch
git log
```

You may check out to stable release build.

```
git checkout -b v1.8.0
```

Note that while newer builds may introduce bugs, they often also fix many. So reverting to a tagged release or branch may defeat the purpose of building it in the first place.

## Build the capture and viewer

See the build script for options.

```
./easybutton-build.sh --help
```

Then build moloch as **vagrant** user into a local directory. No root user here.

```
./easybutton-build.sh --dir /home/vagrant/install/moloch
```

Dependencies should be downloaded by the script if executed on supported OS. Note that build will already create the install directory and place nodejs binaries there, but as root because that command is executed via sudo. Make sure that user can write to install directory before proceeding.

```
sudo chown -R vagrant:vagrant /home/vagrant/install/moloch
make install
/home/vagrant/install/moloch/bin/moloch-capture --help
```

## Deploy the database

Before moving on to basic config, make sure that elasticsearch is up and running. Easiest way to deploy it nowadays is to simply run from docker image.

```
sysctl -w vm.max_map_count=262144
docker run -ti --name moloch-elastic -p 9200:9200 -e "discovery.type=single-node" -e "node.name=moloch" -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" -e "cluster.name=cdmcs" docker.elastic.co/elasticsearch/elasticsearch-oss:6.7.0
```

Add `-d` and `--restart=always` if you wish to run image as background daemon. Once up, verify connectivity by quering the `_cat` api for meta.

```
curl localhost:9200/_cat/indices
curl localhost:9200/_cat/nodes
curl localhost:9200/_cat/shards
curl localhost:9200/_cat/health
```

See [here](/Suricata/indexing#documents-and-mappings) for more information about documents, shards and indices. Otherwise, use the bundled database script to create a fresh db.

```
cd /home/vagrant/install/moloch/db
./db.pl localhost:9200 init
```

See `db.pl` without any arguments to see what the script can do. For example, important tables can be backed up using `db.pl localhost:9200 backup /dir/prefix` command. Then verify that indices exist.

```
vagrant@moloch-build:~/install/moloch/db$ curl localhost:9200/_cat/indices
green open users_v6    uayjaGk9Rpmehq0Hwb3PQw 1 0  0 0   230b   230b
green open dstats_v3   MDAjXDl7SWCQ0aRLvFRwaQ 2 0  0 0   460b   460b
green open fields_v2   4Z53e199SayXH7EGOs5_ZA 1 0 42 0 22.3kb 22.3kb
green open hunts_v1    9gQOxhNmS92Fm4alO1lTKg 1 0  0 0   230b   230b
green open sequence_v2 JhsIV_4OSZ6PgSSdJrLW7w 1 0  0 0   230b   230b
green open stats_v3    D60raa3SSdqsjfq88ZhS5Q 1 0  0 0   230b   230b
green open files_v5    dc5uqE5PS1OfRpwp7GmYEQ 2 0  0 0   460b   460b
green open queries_v2  ZeTjw9rXQImI7olqomhyoQ 1 0  0 0   230b   230b
```

## Download geoip database files

```
/home/vagrant/install/moloch/bin/moloch_update_geo.sh
```

# Config

See:
 * https://github.com/aol/moloch/wiki/Settings#Basic_Settings

Create a new config file.

```
cd /home/vagrant/install/moloch/etc
cp config.ini.sample config.ini
```

Replace the install dir placeholder.

```
sed -i -e "s,MOLOCH_INSTALL_DIR,/home/vagrant/install/moloch,g" config.ini
```

In `config.ini`:

 * Point moloch to correct elastic instance. Multiple elastic proxies can be delimited by comma. In that case, moloch will send bulks in round-robin;

```
elasticsearch=localhost:9200
```

 * Set a secret string for password hashing;

```
passwordSecret = CHOOSE_SOMETHING
```

 * Configure listening interfaces. See `ip link show` for list of available devices;

```
interface=enp0s3;enp0s8
```

 * Configure pcap directory. Default is fine as an exercise, but this is where your large disk is mounted. 

```
pcapDir = /home/vagrant/data
```

Pcap directory must exist and be writeable to moloch `dropUser` or `dropGroup`. Otherwise, [exit may not be graceful](https://github.com/cuckoosandbox/cuckoo/issues/2543).

```
dropUser=vagrant
dropGroup=vagrant
```

```
mkdir -p /home/vagrant/data
chown vagrant:vagrant /home/vagrant/data
```

You should now be able to start capture.

```
cd ~/install/moloch/bin
```

```
./moloch-capture -c ../etc/config.ini
```

Verify connections in database and disk. You should see `sessions2_XXX` indices.

```
curl -ss localhost:9200/_cat/indices | sort -h
```

```
sudo tcpdump -n -r ~/data/moloch-build-190416-00000011.pcap
```

Go to the viewer directory, create a new admin user and start the server.

```
cd /home/vagrant/install/moloch/viewer
../bin/node addUser.js -c ../etc/config.ini admin admin admin --admin
../bin/node viewer.js -c ../etc/config.ini
```

Then visit port `8005` in browser for your VM private network. Run `curl` commands against popular web sites to generate some traffic inside the build VM.

# Tasks

## Basic

  * Set up moloch with **hourly** index pattern that stores pcap files in **/srv/pcap** folder as **moloch** user;
    * Ensure that viewer is able to **see and open** all sessions;

## Advanced

  * Refer to example configs in moloch `etc` folder and [singlehost](/Moloch/vagrant/singlehost) provisioning script, create persistent systemd services for capture and viewer;
    * Ensure that moloch services are started after `docker` service;
