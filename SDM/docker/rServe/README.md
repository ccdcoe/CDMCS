# Rserve in docker

Rserve is a library that opens a TCP interface to R interpreter, thus allowing you to interface with R from other programming languages or machines (think gpuR on server while writing code from remote workstation). This repository packages R and rserve library into a portable docker definition. Image can be built using the following command:

```
docker build -t ccdcoe/rserve .
```

Optionally, container user name can be specified using command-line arguments:

```
docker build -t ccdcoe/rserve --build-arg user=vagrant .
```

```
PROJECT=$HOME/CDMCS/SDM/docker/rServe
DATA=$HOME/data
```
```
docker run --rm -ti -v $PROJECT:/home/vagrant -v $DATA:/mnt ccdcoe/rserve
```
