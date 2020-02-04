# Exploring the data

Having alert or network log on disk may be nice, but that approach does not really scale. Hunting needs tools that scale and can aggregate vast amounts of data. Because suricata can produce. Nowadays, [elastic stack](https://www.elastic.co/products) is the go-to method for doing that. Most front-end tools simply rely on elastic aggregations.

## Playing with python

Great tool for quick **interactive** scripting against data is to simply use a Jupyter notebook. Setting it up as regular user on modern machine with python3 is quite straightforward.

```
python3 -m pip install --user --upgrade jupyter jupyterlab
```

It is also a good idea to install some additional packages needed for interacting with our data sources.

```
python3 -m pip install --user elasticsearch redis pandas
```

Make sure that notebook is running. 

```
jupyter lab --ip=XXXX
```

Note that `ip` is needed if running notebook inside a vagrant VM, and it should correspond to private address of box that is accessible from hypervisor. Then look for the following line in console output:

```
    To access the notebook, open this file in a browser:
        file:///run/user/1000/jupyter/nbserver-11679-open.html
    Or copy and paste one of these URLs:
        http://ADDRESS:8888/?token=<TOKEN>
```

Then copy the URL into host machine browser if running jupyter inside Vagrant VM. Otherwise, if running from classroom laptop, the notebook should try to open the link with default browser.

See `.ipynb` files for additional content.

# Frontends

There are many tools for hunting and dashboarding. However, you should first set up elastic and indexing pipeline before you can set them up.

## Evebox

> Web Based Event Viewer (GUI) for Suricata EVE Events in Elastic Search

 * https://evebox.org/
 * https://github.com/jasonish/evebox

### Installing

Evebox is written in golang, so you actually just need to download a binary.

see:
 * https://evebox.org/files/development/
 * https://evebox.org/files/release/latest/

But there's nothing like firing up another container to host a simple Go binary.

```
docker pull jasonish/evebox
docker run -it -p 5636:5636 jasonish/evebox:master -e http://elasticsearch:9200
```

[Remember docker networks](/common/docker.md#networking) if experiencing elastic connectivity errors. Or use exposed host port, provided elastic is not limited to localhost.

```
docker run -it -p 5636:5636 --network elastic jasonish/evebox:master -e http://elasticsearch:9200
```

Up to you.

### Linking to elasticsearch

See evebox arguments.

```
evebox -h
```

**Do not expect an error message if elastic aggregation fails in background**. Just think of debuggin as fun little game. 

If running evebox from console gives no error but inbox/alerts displays no logs while events, then it's likely one of those problems:
 * events lack `.keyword` (es 5+) or `.raw` (es 2) field mappings;
   * or elasticsearch keyword argument missing;
   * missing index template;
 * event `@timestamp field missing`;

If events shows no logs while console displays no elastic connectivity errors, then your index pattern is likely wrong.

See `/etc/default/evebox` if installing from deb package.

## Scirius

> Scirius is a web application for Suricata ruleset management.

 * https://github.com/StamusNetworks/scirius
 * https://scirius.readthedocs.io/en/latest/installation-ce.html
 * https://www.stamus-networks.com/open-source/

### Setup

Scirius is a web application written on django framework. Nowadays it also includes nodejs, which has had some...issues. Official documentation works, this guide simply serves as helper on some important considerations.

Set up some python2 dependencies and clone the repo. Checkout version is out of date if you are from the future.

```
apt-get install -y python-pip dbconfig-common sqlite3 python-virtualenv
git clone https://github.com/StamusNetworks/scirius
cd scirius
```

Then start up virtualenv in local scirius folder. Install local deps into venv.

```
/usr/local/bin/virtualenv ./
source ./bin/activate

pip install -r requirements.txt
pip install --upgrade urllib3
pip install gunicorn pyinotify python-daemon
```

This is where the real *fun* begins. Let's pull a node version that actually works, set it up locally and freeze all versions. It's the [javascript way](https://en.wikipedia.org/wiki/Electron_(software_framework)).

```
NODE_VERSION="v10.18.1"
wget -4 -q https://nodejs.org/dist/$NODE_VERSION/node-$NODE_VERSION-linux-x64.tar.xz
tar -xJf node-$NODE_VERSION-linux-x64.tar.xz 
```

Remember those *issues* I mentioned earlier? Well, once upon a time, `npm` as `root` blew up your entire `/etc`. So now, if you try to build node packages as root user, you are going to have a bad time. Because, [nodejs modules written in c++](http://benfarrell.com/2013/01/03/c-and-node-js-an-unholy-combination-but-oh-so-right/) is a thing. So, everything is done as `vagrant` user with explicitly configured node module directory and paths.

```
mkdir ~/.npm-global
echo 'export PATH=~/.npm-global/bin:$PATH' > ~/.profile
echo "export PATH=$PWD/node-$NODE_VERSION-linux-x64/bin:\$PATH" > ~/.profile
source ~/.profile

npm config set prefix '~/.npm-global'
```

Now we can proceed with official guidelines.

```
npm install -g npm@latest webpack@3.11
npm install
cd hunt
npm install
npm run build
cd ..
```

Run database migrations.

```
python manage.py migrate
```

Generate CSS stuff.

```
/home/vagrant/.npm-global/bin/webpack
```

Collect static CSS assets.

```
python manage.py createsuperuser
```

Then see [local cofiguration](https://github.com/ccdcoe/CDMCS/blob/2019/Suricata/vagrant/singlehost/provision.sh#L652) for pointing scirius to elastic.

## Kibana

The most well-known frontend for elastic stack. And easiest to set up. Basic config involes just pointing toward elastic proxy. Note that image should be in same private network as elasticsearch cluster if docker is used. Alternatively, kibana can also be pointed toward exposed elastic proxy on host. Default port is `5601`, host port should be forwarded there to enable http access.

```
docker run \
  -it \
  --name kibana \
  -h kibana \
  --network cdmcs  \
  -e "SERVER_NAME=kibana" \
  -e "ELASTICSEARCH_URL=http://elastic:9200" \ # Deperecated in elastic 7 in favor of ELASTICSEARCH_HOSTS
  -p 5601:5601 \
    docker.elastic.co/kibana/kibana-oss:7.5.2
```

Then visit exposed port in web browser. Create a new index pattern under `management` > `Index Patterns`. This will allow you to use `Discover` and `Visuzalize` tabs. But most useful tab by far is `Dev tools` which functions as autocomplete-enabled IDE for elastic API. You can test any previously used curl or python queries in this tab.

## Alerta

Alerting tends to turn whatever tool is used into a log server. E-mail is especially bad for this. But you need to know what the situation is right now, how the alert levels have elevated or dropped, how the alerts correspond to your assets, how the alerts are correlated, etc. Alerta is the tool for doing that.

 * https://docs.alerta.io/en/latest/quick-start.html

Alerta is simply a python API supported by a mongodb database (though is not the only option). Firstly, we need to set up our mongo instance. There are two methods:

 * [set up debian ppa](https://docs.mongodb.com/master/tutorial/install-mongodb-on-ubuntu/)
 * [use a docker image](https://docs.docker.com/samples/library/mongo/)

Mongo only needs to be accessible to alerta api daemon. And `localhost` is good enough for testing environment. Then install CLI tool and daemon from pip. Note that `$HOME/.local/bin` should be in path for subsequent commands.

```
python3 -m pip install --user alerta alerta-server
```

Then run the API server with default options while listening to all interfaces. Listening part is important because old web ui uses *CORS*.

```
alertad run --port 8080 --host 0.0.0.0
```

Speaking of *CORS*, we should update `/etc/alertad.conf` (or local version if you modified `ALERTA_SVR_CONF_FILE` env variable) for the ip/domain/port that will later be used for web ui!

```
CORS_ORIGINS = [
    'http://192.168.10.15:8000'
]
```

Note that you should use whatever IP/Port you decide to use. Vagrant box public ip should be added and port `8000` is simply for reference. Then set up the web ui.

```
wget -O alerta-web.tgz https://github.com/alerta/angular-alerta-webui/tarball/master
tar zxvf alerta-web.tgz
cd alerta-angular-alerta-webui-*/app
python3 -m http.server 8000
```

Make sure to edit `config.json` in `app` directory to point to correct endpoint.

```
{"endpoint": "http://192.168.10.15:8080"}
```

Due to *CORS*, this endpoint should be exposed to the user. So, localhost is not going to be good if you are serving it remotely.

**Important!** - Old web ui is deprecated. See [new web ui](https://github.com/alerta/beta.alerta.io) for future reference.

### Usage

Web ui is simply for colorful pictures, first verify that everything works via command line tool.

```
alerta send -r web01 -e NodeDown -E Production -S Website -s major -t "Web server is down." -v ERROR
```
```
alerta top
```

Then see the web ui. If it does not work, it is most likely *CORS* or *endpoint* in `app/config.json`

### Config

 * https://docs.alerta.io/en/latest/configuration.html?highlight=levels

Many things can be customized, including alert levels.

```
SEVERITY_MAP = {
    'erm, what!??': 1,
    'wat': 2,
    'interesting': 3,
    'ok': 4,
    'meh': 5
}
DEFAULT_NORMAL_SEVERITY = 'ok'  # 'normal', 'ok', 'cleared'
DEFAULT_PREVIOUS_SEVERITY = 'interesting'

COLOR_MAP = {
    'severity': {
            'erm, what!??': "red",
            'wat': "orange",
            'interesting': "yellow",
            'ok': "skyblue",
            'meh': "green"
    },
    'text': 'black',
    'highlight': 'skyblue '
}
```

### Housekeeping

Expired alerts do not go away by themselves, they have to be clean up via periodic cleanup job. Edit the crontab via `crontab -e`.

```
* * * * *  alerta housekeeping
```

---

[back](/Suricata)
