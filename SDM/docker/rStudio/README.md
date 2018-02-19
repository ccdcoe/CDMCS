# Rstudio in docker

This repository packages R and GUI RStudio IDE into a portable docker definition, using ubuntu 16.04 base image. Image can be built using the following command:

```
docker build -t ccdcoe/rstudio .
```

Optionally, rstudio installer version and container user name can be specified using command-line arguments:

```
docker build -t ccdcoe/rstudio --build-arg user=vagrant --build-arg rstudio="rstudio-xenial-1.1.423-amd64.deb" .
```
