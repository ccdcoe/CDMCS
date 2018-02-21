# Jupyter notebook

## build it

```
docker build -t ccdcoe/sdm-jupyter .
```

## running it
```
docker run -it --rm -p 8888:8888 -v $PWD:/home/jovyan/books ccdcoe/sdm-jupyter
```
