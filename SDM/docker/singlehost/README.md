# singlehost docker environment

```
docker-compose build && docker-compose up
```

## data directory

If you are running docker through sudo, then data directory will not be mounted properly (as you are actually root). You may need to set home directory manually.
```
sudo bash -c "export HOME=/home/markus && docker-compose up"
```
