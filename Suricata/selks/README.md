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
./easy-setup.sh
```

At the end of this run you will have:
* docker installation;
* docker-compose;
* portainer for managing docker containers (if enabled);
* prepared data for containers;
* af-packet interface capture config for suricata;
* environment setup for Elastic and Logstash memory caps;

Alternatively, script can also be executed non-interactively with most options passed via command line. Make sure that interface `-i` matches something that exists on your system.

```
./easy-setup.sh  --non-interactive -i tppdummy0 --iA --es-memory 1G --ls-memory 1G
```

Refer to live capture section on for how to set up a virtuan NIC for replays.

Once setup is done, spin up containers with docker-compose.

```
docker-compose up -d
```

To see the logs either omit the `-d` to call it in foreground or see the backend logs.

```
docker-compose logs --follow
```
