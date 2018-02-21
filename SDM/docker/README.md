# Docker environments

## Generic networking

* https://docs.docker.com/config/containers/container-networking/

## Linking containers

If you want two containers to be able to talk to each other, then use identical `--network` parameter for both. Defined network must exist on the system first.

```
docker network ls
```
