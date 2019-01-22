# Indexing alert log

Having alert or network log on disk may be nice, but that approach does not really scale. Hunting needs tools that scale and can aggregate vast amounts of data. Because suricata can produce. Nowadays, [elastic stack](https://www.elastic.co/products) is the go-to method for doing that. Most front-end tools simply rely on elastic aggregations.

## Intro

Go through attached jupyter notebooks.

 * [Playing with eve.json](001-load-eve.ipynb)
 * [Getting started with elasticsearch](002-elastic-intro.ipynb)

Make sure that notebook is running. As `vagrant` user in `indexing` box, run the following command.

```
jupyter lab --ip=192.168.10.14
```

Note that `ip` is needed if running notebook inside a vagrant VM, and it should correspond to private address of box that is accessible from hypervisor. Then look for the following line in console output:

```
    To access the notebook, open this file in a browser:
        file:///run/user/1000/jupyter/nbserver-11679-open.html
    Or copy and paste one of these URLs:
        http://192.168.10.14:8888/?token=<TOKEN>
```

Then copy the URL into host machine browser. Local notebooks are accessible under `localbox` sync point.
