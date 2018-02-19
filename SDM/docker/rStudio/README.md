# Rstudio in docker

This repository packages R and GUI RStudio IDE into a portable docker definition, using ubuntu 16.04 base image. Image can be built using the following command:

```
docker build -t ccdcoe/rstudio .
```

Optionally, rstudio installer version and container user name can be specified using command-line arguments:

```
docker build -t ccdcoe/rstudio --build-arg user=vagrant --build-arg rstudio="rstudio-xenial-1.1.423-amd64.deb" .
```

GUI image can then be started with following docker command line arguments. It is necessary to pass X11 unix socket and display variables to initiate working graphical app. `/dev/dri` is used to pass intel GPU drivers to the container. Workspace image and user-installed packages will be placed under user home dir, thus I would recommend mounting the project folder on host to container home directory. I would also recommend separating code and data directories.

```
PROJECT=$HOME/CDMCS/SDM/docker/rStudio
DATA=$HOME/data
```
```
docker run --rm -ti -e "DISPLAY" -v /tmp/.X11-unix/:/tmp/.X11-unix --device=/dev/dri:/dev/dri -v $PROJECT:/home/vagrant -v $DATA:/mnt ccdcoe/rstudio
```
