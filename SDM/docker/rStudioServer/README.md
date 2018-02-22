# Rstudio in docker

* https://hub.docker.com/r/rocker/rstudio/

```
PROJECT=$HOME/CDMCS/SDM/docker/rStudioServer
DATA=$HOME/data
```
```
docker run -d -p 8787:8787 rocker/rstudio
```
