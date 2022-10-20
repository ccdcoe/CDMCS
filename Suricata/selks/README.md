# SELKS

## On docker

Simply clone the SELKS public repository.

```
git clone https://github.com/StamusNetworks/SELKS.git
```

Enter the docker folder.

```
cd SELKS/docker
```

Use `easy-setup.sh` script to prepare docker environment. It will prompt with a number of questions, including. Install what is needed.

```
sudo ./easy-setup.sh --es-memory 1G --ls-memory 1G
```

Note that this command limits Elasticsearch and Logstash memory to 1GB RAM.

At the end of this run you will have:
* docker installation;
* docker-compose;
* portainer for managing docker containers (if enabled);
* prepared data for containers;
* af-packet interface capture config for suricata;
* environment setup for Elastic and Logstash memory caps;

Alternatively, script can also be executed non-interactively with most options passed via command line. Make sure that interface `-i` matches something that exists on your system.

```
sudo ./easy-setup.sh  --non-interactive -i tppdummy0 --iA --es-memory 1G --ls-memory 1G
```

Refer to live capture section on for how to set up a virtuan NIC for replays.

Once setup is done, spin up containers with docker-compose.

```
sudo docker-compose up -d
```

To see the logs either omit the `-d` to call it in foreground or see the backend logs.

```
sudo docker-compose logs --follow
```

Once done, navigate to `https://192.168.56.13/` if using embedded vagrant env. Otherwise visit port 443 on whatever box was used. Default credentials are `selks-user:selks-user`.

## Reading PCAPs

`SELKS/docker/scripts` folder has a helper for reading PCAP files.

```
./scripts/readpcap.sh -h
Pcap reading script through Suricata
Usage: ./scripts/readpcap.sh [-c|--(no-)cleanup] [-a|--(no-)autofp] [-s|--set-rulefile <arg>] [-S|--set-rulefile-exclusive <arg>] [-h|--help] [--] <path>
        <path>: Path to the pcap file to read. If <path> specifies a directory, all files in that directory
                will be processed in order of modified time maintaining flow state between files.
        -c, --cleanup, --no-cleanup: Remove all previous data from elasticsearch and suricata. (off by default)
        -a, --autofp, --no-autofp: Run in autofp mode instead of single mode. (off by default)
        -s, --set-rulefile: Set a file with signatures, which will be loaded together with the rules set in the yaml. (no default)
        -S, --set-rulefile-exclusive: Set a file with signatures, which will be loaded exclusively, regardless of the rules set in the yaml. (no default)
        -h, --help: Prints help

Usage: readpcap.sh [OPTIONS] <path>
```

To read a single PCAP file in Suricata `autofp` mode, use following command. Note the `-c` flag which also cleans up any previously existing data.

```
sudo ./scripts/readpcap.sh -ac /data/2021-01-06-Remcos-RAT-infection.pcap
```

By navigating to **hunt** section and selecting **all** from **time picker**, you should see something like this.

![Hunt view](hunt-pcap-read.png)

# Suricata Analytics

Suricata Analytics is a project by Stamus Networks to develop Jupyter notebooks for EVE data exploration and threat hunting. Project can be cloned from public github repo:

```
git clone https://github.com/StamusNetworks/suricata-analytics
```

Within the confines of this training, we recommend setting up a python virtual environment for `docker-compose`.

```
cd suricata-analytics
python3 -m venv .venv
source .venv/bin/activate
pip install docker-compose
```

Then build the container locally.

```
docker-compose build
```

Before starting the stack, make sure to set up `.env` file. Simply copy the packaged reference.

```
cp .env.example .env
```

Then edit the file. 
* `SCIRIUS_TOKEN` can be found (or generated) in SELKS UI. Click on your username on top-right corner, go to `account settings`, then click `Edit Token` on left-hand menu under `User Settings` box. If the token is empty, simply click `Regenerate`. Then copy and paste the value into env file.
* `SCIRIUS_HOST` will be the IP hosting SELKS instance. If using Vagrant, it will be the day3-selks box on `192.168.56.13`
* `SCIRIUS_TLS_VERIFY` must be `no` since training setup uses default self-signed certificate

```
SCIRIUS_TOKEN=<TOKEN>
SCIRIUS_HOST=192.168.56.13
SCIRIUS_TLS_VERIFY=no
```

Once this is done, start the docker env.

```
docker-compose up -d
```

You need API authentication token from jupyter logs. Search for the following lines:

```
(.venv) vagrant@day3-clean:~/suricata-analytics$ docker-compose logs
...
stamus_jupyter | [I 2022-10-14 14:47:54.615 ServerApp] Use Control-C to stop this server and shut down all kernels (twice to skip confirmation).
stamus_jupyter | [C 2022-10-14 14:47:54.617 ServerApp]
stamus_jupyter |
stamus_jupyter |     To access the server, open this file in a browser:
stamus_jupyter |         file:///home/jovyan/.local/share/jupyter/runtime/jpserver-6-open.html
stamus_jupyter |     Or copy and paste one of these URLs:
stamus_jupyter |         http://8ed1eee366bf:8888/lab?token=0c7c34ada0ad6243decb1dcbb3654c1b9de2b423a10d2678
stamus_jupyter |      or http://127.0.0.1:8888/lab?token=0c7c34ada0ad6243decb1dcbb3654c1b9de2b423a10d2678
```

Note that you must modify the IP to reflect your server. Meaning that `http://127.0.0.1:8888/lab?token=0c7c34ada0ad6243decb1dcbb3654c1b9de2b423a10d2678` becomes `http://192.168.56.13:8888/lab?token=0c7c34ada0ad6243decb1dcbb3654c1b9de2b423a10d2678` (if using vagrant env).

# Tasks

* get SELKS up and running
* set up rule server with `python3 -m http.server`
  * set up a rule source in scirius and attach it to suricata
* enable `tgreen/hunting` ruleset
* import `2021-01-06-Remcos-RAT-infection`
  * what is the malicious domain used for stage1?
  * find the malicious EXE
  * what is the IP used to serve it?
* import `2021-01-05-PurpleFox-EK-and-post-infection-traffic`
  * what is the IoC for malicious host?
  * look into `flow` records, does anything seem strange?
* import `2022-01-01-thru-03-server-activity-with-log4j-attempts`
  * find encoded log4j script injection
  * decode it

