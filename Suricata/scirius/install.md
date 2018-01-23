# Scirius install on Debian | Ubuntu

before install please see [elasticsearch](/common/elastic)

## prereqs

### external deps and tools
```
apt-get install -y nginx python-pip dbconfig-common sqlite3
```
### python stuff (global)
```
pip install --upgrade pip virtualenv
```

## from deb

```
SCIRIUS="scirius_1.2.7-1_amd64.deb"
[[ -f $SCIRIUS ]] || wget $WGET_PARAMS http://packages.stamus-networks.com/selks4/debian/pool/main/s/scirius/$SCIRIUS -O $SCIRIUS

apt-get install -y nginx python-pip dbconfig-common sqlite3 > /dev/null
pip install --upgrade pip virtualenv #urllib3 chardet

```

## from git

see:
* https://github.com/StamusNetworks/scirius#installation-and-setup

```
git clone https://github.com/StamusNetworks/scirius.git && git checkout tags/scirius-1.2.8 && cd scirius
```

### create virtualenv
```
/usr/local/bin/virtualenv ./
source $SCIRIUS_PATH/bin/activate
```

### install internal deps
```
pip install -r requirements.txt
pip install --upgrade urllib3
pip install gunicorn pyinotify python-daemon
```

### create database

```
python manage.py syncdb #--noinput
```

### create your own superuser (in a script)

```
echo "from django.contrib.auth.models import User; User.objects.create_superuser('vagrant', 'vagrant@localhost', 'vagrant')" | python manage.py shell
```

----

Next -> [configuration](config.md)
