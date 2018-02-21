# Jupyter notebook

* http://jupyter-notebook-beginner-guide.readthedocs.io/en/latest/what_is_jupyter.html
* [Based on official jupyter-datascience image](https://github.com/jupyter/docker-stacks)
* [this image also supports Golang](https://github.com/gopherdata/gophernotes)
 
## build it

```
docker build -t ccdcoe/sdm-jupyter .
```

## run it

Make sure that repo mount point is correct.

```
docker run -it --rm -p 8888:8888 -v $HOME/CDMCS/SDM:/home/jovyan/books ccdcoe/sdm-jupyter
```

In case you want to mount your local working directory

```
docker run -it --rm -p 8888:8888 -v $PWD:/home/jovyan/books ccdcoe/sdm-jupyter
```

Do not mount over jovyan home directory as Go kernel might not work any more.
