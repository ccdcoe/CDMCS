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

## Basic usage

### install docker-ce on ubuntu

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

### List images on system
```
docker images
```

### Pull image from public repository

* https://docs.docker.com/engine/reference/commandline/run/

```
docker pull debian:stretch
docker run -ti --rm --name firstcontainer debian:stretch
```

### Execute any command inside running container
```
docker exec -ti firstcontainer /bin/bash
```

### Building a new container 

* https://docs.docker.com/engine/reference/builder/

```
vim $PWD/Dockerfile
```
```
FROM debian:stretch

RUN apt-get update && apt-get install -y bash

CMD /bin/bash -c "echo useless"
```
```
docker build -t ccdcoe/useless .
```

### Run multiple containers

* https://docs.docker.com/compose/

```
apt-get install docker-compose
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
