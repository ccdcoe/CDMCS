# Docker

* https://docs.docker.com/get-started/
* https://docs.docker.com/compose/gettingstarted/
* https://docs.docker.com/engine/reference/builder/

## Docker is
* an application containerization tool
* not a virtualization platform (container contents are executed on host)

## Install
* https://docs.docker.com/install/linux/docker-ce/ubuntu/
* https://wiki.archlinux.org/index.php/Docker

## install docker-ce on ubuntu

Always use up to date version of docker engine.

```
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
```
```
apt-get update && apt-get install docker-ce
```
```
systemctl start docker
systemctl enable docker
```

## List images on system

Docker is designed around images which are in turn used to deploy new containers. An image is simply a stack of virtual file system diffs layered upon each other. In other words, deploying a new container does not copy base image data as is often the case with virtual machines, but only creates a volatile diff.

Locally present images can be listed with following command.

```
docker images
```

## Pull image from public repository

* https://docs.docker.com/engine/reference/commandline/run/

New images can be pulled from public or private registries. Pull can be done explicitly with `docker pull` but us not needed. Invoking `docker run` on locally missing container will cause the deamon to automatically pull the image if it exists in configured registry. [Docker hub](https://hub.docker.com/) is used by default. So be careful what you pull. Each image can have tags. In other words, `debian:stretch` and `debian:jessie` are not two distinct images, but rather two versions of the same container.

```
docker pull debian:stretch
docker run -ti --rm --name firstcontainer debian:stretch
```

## Execute any command inside running container

You can enter a running container with `exec` subcommand. Note that `-ti` is needed to keep console stdout open. Containers can be entered using container `--name` or id that can be found using `docker ps` command. Container that does not have explicit name configured will get a random name from the daemon.

```
docker exec -ti firstcontainer /bin/bash
```

## Building a new container 

* https://docs.docker.com/engine/reference/builder/

Containers are not configured nor used manually. Exec should only be used to debug build or networking issues. Custom images are built using a `Dockerfile`.

```
vim $PWD/Dockerfile
```

Each line in Dockerfile corresponds to a differential file system layer. The following command `apt-get` is written as one line because this approach will update the cache temporarily during build time, install bash shell and then clean up local package manager cache. Installed package would remain in the image by cache will not. In other words, separating `install` and `autoremove` commands to two distinct lines would result in package cache remain in the first layer and therefore the image size will be significantly larger.

```
FROM debian:stretch

RUN apt-get update && apt-get install -y bash && apt-get -y autoremove && apt-get -y autoclean

CMD /bin/bash -c "echo useless"
```

Build command can then be executed in local directory, defined by `.`.

```
docker build -t local/useless .
```

## Run multiple containers

* https://docs.docker.com/compose/

Many methods exist to run multiple containers. For example, a web site usually depends on a database. A correct *docker way* would be to separate those two into two distinct containers, as each container is designed to handle a single application with `PID` 1.

```
apt-get install docker-compose
#python3 -m pip install --user --upgrade docker-compose
vim docker-compose.yml
```
```
version: '3'
services:
  web:
    image: httpd
    ports:
     - "5000:5000"
  redis:
    image: "redis:alpine"
```
```
docker-compose up
```

## Networking

Docker containers are relegated to private bridge networks. A single container that does not have `--network` flag defined would therefore be assigned to a private network. Services inside containers are exposed to host using port forwarding.

The following command would forward local port 88 to internal container port 80 when starting a web server.

```
docker run -ti -p localhost:88:80 httpd
```

Existing networks can be seen using `docker network ls` command. Following commands would create a new network with `bridge` driver and add two elastic stack containers there.

```
DOCKER_ELA="docker.elastic.co/elasticsearch/elasticsearch-oss:6.5.4"
DOCKER_KIBANA="docker.elastic.co/kibana/kibana-oss:6.5.4"

docker network create -d bridge cdmcs
docker run -it -d --name elastic -h elastic --network cdmcs -p 127.0.0.1:9200:9200 $DOCKER_ELA 
docker run -it -d --name kibana -h kibana --network cdmcs  -e "ELASTICSEARCH_URL=http://elastic:9200" -p 5601:5601  $DOCKER_KIBANA
```

Note that containers commonly allow configuration via environmental variables. This support has to be built into individual container, so refer to image documentation for supported variables. In this example, `ELASTICSEARCH_URL` configures connection URL in kibana container to be `http://elastic:9200`, whereas *elastc* refers to `--name` of first container. Internal docker proxy will handle the name resolution as container internal IP addresses are assigned dynamically. Note that `-h` sets the internal hostname string for container.  This has no effect on name resolution, but cab be useful for logging as syslog hostname field would be randomly generated string that is not consistent between container redeployments.

Note that docker-compose will automatically handle this common network unless explicitly configured.

## Persistence

Docker file system is volatile and should only be used to store application code, dependencies, and critical system tools and libraries. No data should be stored there unless it is for testing or development! Furthermore, Docker file system layers can degrade the performance of IO intensive application.

A simple solution would be to map a local file system folder as docker volume with `-v` flag.

```
docker run -it -d -v /home/user/appdata:/usr/share/elasticsearch/data -p 127.0.0.1:9200:9200 $DOCKER_ELA 
```

Note that *UID* inside the container must have write permissions to the host folder, otherwise the app will fail. It is possible to also remap the UID via docker command line flags, but a proper way to handle this is to create a dedicated volume.

```
docker volume create myvol
docker run -it -d -v myvol:/usr/share/elasticsearch/data -p 127.0.0.1:9200:9200 $DOCKER_ELA 
```

Note that this volume is not using docker virtual filesystems and is actually kept separate on host filesystem (unless using alternative drivers). Verify the data by looking into docker data dir.

```
ls -lah /var/lib/docker/volumes/
```
