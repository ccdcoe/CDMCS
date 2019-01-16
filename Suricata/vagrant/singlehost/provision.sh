check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive|failed" && systemctl start $1.service
  systemctl status $1.service
}

# params
DOCKERIZE=true
DEBUG=true
PROXY=http://192.168.10.1:3128
EXPOSE=192.168.10.11
PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"

# versions
ELA="elasticsearch-oss-6.5.4.deb"
KIBANA="kibana-oss-6.5.4-amd64.deb"
LOGSTASH="logstash-oss-6.5.4.deb"
INFLUX="influxdb_1.7.3_amd64.deb"
TELEGRAF="telegraf_1.9.2-1_amd64.deb"
GRAFANA="grafana_5.4.3_amd64.deb"
EVEBOX="evebox_0.10.1_amd64.deb"
SCIRIUS="scirius_3.1.0-1_amd64.deb"

SCIRIUS_PATH="/opt/scirius"
SCIRIUS_CONF=$SCIRIUS_PATH/scirius/local_settings.py

DOCKER_ELA="docker.elastic.co/elasticsearch/elasticsearch-oss:6.5.4"
DOCKER_KIBANA="docker.elastic.co/kibana/kibana-oss:6.5.4"
DOCKER_LOGSTASH="docker.elastic.co/logstash/logstash-oss:6.5.4"
DOCKER_EVEBOX="jasonish/evebox"

start=$(date)

# basic OS config
FILE=/etc/sysctl.conf
grep "disable_ipv6" $FILE || cat >> $FILE <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p

echo "Configuring DOCKER"
docker network ls | grep cdmcs >/dev/null || docker network create -d bridge cdmcs

echo "Provisioning REDIS"
# no persistent storage, only use as mem cache
docker ps -a | grep redis || docker run -dit --name redis -h redis --network cdmcs --restart unless-stopped -p 127.0.0.1:6379:6379 --log-driver syslog --log-opt tag="redis" redis

FILE=/etc/apt/apt.conf.d/99force-ipv4
[[ -f $FILE ]] ||  echo 'Acquire::ForceIPv4 "true";' | sudo tee $FILE
export DEBIAN_FRONTEND=noninteractive
mkdir -p /vagrant/pkgs

# basic software
apt-get update > /dev/null && apt-get install -y curl htop vim tmux software-properties-common python3-software-properties jq python3 python3-pip > /dev/null

# suricata
install_suricata_from_ppa(){
  add-apt-repository ppa:oisf/suricata-stable > /dev/null 2>&1 \
  && apt-get update > /dev/null \
  && apt-get install -y suricata > /dev/null
}
echo "Provisioning SURICATA"
suricata -V || install_suricata_from_ppa
pip3 install --upgrade suricata-update

touch  /etc/suricata/threshold.config
mkdir -p /var/lib/suricata/rules
[[ -f /var/lib/suricata/rules/scirius.rules ]] || touch /etc/suricata/rules/scirius.rules
[[ -f /var/lib/suricata/rules/suricata.rules ]] || touch /etc/suricata/rules/suricata.rules

if $DEBUG ; then ip addr show; fi
systemctl stop suricata
pgrep Suricata || [[ -f /var/run/suricata.pid ]] && rm /var/run/suricata.pid

echo "Configuring SURICATA"

echo "Adding includes for SURICATA"
FILE=/etc/suricata/suricata.yaml
grep "cdmcs" $FILE || cat >> $FILE <<EOF
include: /etc/suricata/cdmcs-detect.yaml
include: /etc/suricata/cdmcs-logging.yaml
EOF

echo "Adding detects for SURICATA"
FILE=/etc/suricata/cdmcs-detect.yaml
grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
af-packet:
  - interface: enp0s3
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: enp0s8
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
default-rule-path: /var/lib/suricata/rules
rule-files:
 - suricata.rules
sensor-name: CDMCS
EOF

echo "Adding outputs for SURICATA"
FILE=/etc/suricata/cdmcs-logging.yaml

grep "CDMCS" $FILE || cat >> $FILE <<EOF
%YAML 1.1
---
# CDMCS
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: 'yes'
      filetype: redis #regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json
      redis:
        server: 127.0.0.1
        port: 6379
        async: true ## if redis replies are read asynchronously
        mode: list
        pipelining:
          enabled: yes ## set enable to yes to enable query pipelining
          batch-size: 10 ## number of entry to keep in buffer

      types:
        - alert:
            payload: yes             # enable dumping payload in Base64
            payload-buffer-size: 4kb # max size of payload buffer to output in eve-log
            payload-printable: yes   # enable dumping payload in printable (lossy) format
            packet: yes              # enable dumping of packet (without stream segments)
            http-body: yes           # enable dumping of http body in Base64
            http-body-printable: yes # enable dumping of http body in printable format
            metadata: no             # enable inclusion of app layer metadata with alert. Default yes
            tagged-packets: yes
        - http:
            extended: yes     # enable this for extended logging information
        - dns:
            version: 2
        - tls:
            extended: yes     # enable this for extended logging information
        - files:
            force-magic: no   # force logging magic on all logged files
        - drop:
            alerts: yes      # log alerts that caused drops
        - smtp:
            extended: yes # enable this for extended logging information
        - dnp3
        - nfs
        - smb
        - tftp
        - ikev2
        - krb5
        - dhcp:
            enabled: yes
            extended: yes
        - ssh
        - stats:
            totals: yes       # stats for all threads merged together
            threads: yes       # per thread stats
            deltas: yes        # include delta values
        # bi-directional flows
        - flow
        # uni-directional flows
        #- netflow
EOF

#if $DEBUG ; then suricata -T -vvv; fi
[[ -f /etc/init.d/suricata ]] && rm /etc/init.d/suricata
FILE=/etc/systemd/system/suricata.service
grep "suricata" $FILE || cat > $FILE <<EOF
[Unit]
Description=suricata daemon
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/var/run/
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid --af-packet -D -vvv
Type=forking

[Install]
WantedBy=multi-user.target
EOF
check_service suricata

echo "Updating rules"
suricata-update enable-source ptresearch/attackdetection
suricata-update enable-source sslbl/ssl-fp-blacklist
suricata-update enable-source oisf/trafficid
suricata-update add-source cdmcs https://raw.githubusercontent.com/ccdcoe/CDMCS/2018/Suricata/vagrant/singlehost/local.rules
suricata-update list-enabled-sources
suricata-update
suricatasc -c "reload-rules" || exit 1

if [[ !$DOCKERIZE ]]; then
  echo "Provisioning JAVA"
  apt-get install -y openjdk-8-jre-headless
fi

if [[ $DOCKERIZE ]]; then 
  sysctl -w vm.max_map_count=262144
fi

# elastic
echo "Provisioning ELASTICSEARCH"
if [[ $DOCKERIZE ]]; then
  docker ps -a | grep elastic || docker run -dit --name elastic -h elastic --network cdmcs -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" --restart unless-stopped -p 127.0.0.1:9200:9200 --log-driver syslog --log-opt tag="elastic" $DOCKER_ELA 
else
  cd $PKGDIR
  [[ -f $ELA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/elasticsearch/$ELA -O $ELA
  dpkg -s elasticsearch || dpkg -i $ELA > /dev/null 2>&1

  sed -i 's/-Xms1g/-Xms512m/g' /etc/elasticsearch/jvm.options
  sed -i 's/-Xmx1g/-Xmx512m/g' /etc/elasticsearch/jvm.options
fi

check_service elasticsearch
sleep 3

curl -s -XPUT localhost:9200/_template/default   -H'Content-Type: application/json' -d '
{
 "order" : 0,
 "version" : 0,
 "template" : "*",
 "settings" : {
   "index" : {
     "refresh_interval" : "5s",
     "number_of_shards" : 3,
     "number_of_replicas" : 0
   }
 }, "mappings" : {
    "_default_" : {
      "dynamic_templates" : [ {
        "message_field" : {
          "path_match" : "message",
          "match_mapping_type" : "string",
          "mapping" : {
            "type" : "text",
            "norms" : false
          }
        }
      }, {
        "string_fields" : {
          "match" : "*",
          "match_mapping_type" : "string",
          "mapping" : {
            "type" : "text", "norms" : false,
            "fields" : {
              "keyword" : { "type": "keyword", "ignore_above": 256 }
            }
          }
        }
      } ],
      "properties" : {
        "@timestamp": { "type": "date"},
        "@version": { "type": "keyword"},
        "geoip"  : {
          "dynamic": true,
          "properties" : {
            "ip": { "type": "ip" },
            "location" : { "type" : "geo_point" },
            "latitude" : { "type" : "half_float" },
            "longitude" : { "type" : "half_float" }
          }
        }
      }
    }
  }
}
'

# kibana
echo "Provisioning KIBANA"
if [[ $DOCKERIZE ]]; then
  docker ps -a | grep kibana || docker run -dit --name kibana -h kibana --network cdmcs  -e "SERVER_NAME=kibana" -e "ELASTICSEARCH_URL=http://elastic:9200" --restart unless-stopped -p 5601:5601 --log-driver syslog --log-opt tag="kibana" $DOCKER_KIBANA
else
  cd $PKGDIR
  [[ -f $KIBANA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/kibana/$KIBANA -O $KIBANA
  dpkg -s kibana || dpkg -i $KIBANA > /dev/null 2>&1

  FILE=/etc/kibana/kibana.yml
  grep "provisioned" $FILE || cat >> $FILE <<EOF
# provisioned
server.host: "0.0.0.0"
EOF
  check_service kibana
fi

# logstash
grep redis /etc/hosts || echo "127.0.0.1 redis" >> /etc/hosts
grep elastic /etc/hosts || echo "127.0.0.1 elastic" >> /etc/hosts

mkdir -p /etc/logstash/conf.d/
FILE=/etc/logstash/conf.d/suricata.conf
grep "CDMCS" $FILE || cat >> $FILE <<EOF
input {
  file {
    path => "/var/log/suricata/eve.json"
    tags => ["suricata", "CDMCS", "fromfile"]
  }
  redis {
    data_type => "list"
    host => "redis"
    port => 6379
    key  => "suricata"
    tags => ["suricata", "CDMCS", "fromredis"]
  }
}
filter {
  json {
    source => "message"
  }
  if 'syslog' not in [tags] {
    mutate { remove_field => [ "message", "Hostname" ] }
  }
}
output {
  elasticsearch {
    hosts => ["elastic"]
    index => "suricata-%{+YYYY.MM.dd.hh}"
  }
}
EOF

echo "Provisioning LOGSTASH"
if [[ $DOCKERIZE ]]; then
  docker ps -a | grep logstash || docker run -dit --name logstash -h logstash --network cdmcs -v /etc/logstash/conf.d/:/usr/share/logstash/pipeline/ -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" --restart unless-stopped --log-driver syslog --log-opt tag="logstash" $DOCKER_LOGSTASH
  sleep 5
else
  cd $PKGDIR
  [[ -f $LOGSTASH ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/logstash/$LOGSTASH -O $LOGSTASH
  dpkg -s logstash || dpkg -i $LOGSTASH > /dev/null 2>&1
  chown root:logstash /var/log/suricata/eve.json
  /usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/suricata.conf -t || exit 1
  sed -i 's/-Xms1g/-Xms512m/g' /etc/elasticsearch/jvm.options
  sed -i 's/-Xmx1g/-Xmx512m/g' /etc/elasticsearch/jvm.options

  check_service logstash
fi

echo "Provisioning RSYSLOG"
add-apt-repository ppa:adiscon/v8-stable
apt-get update
apt-get install rsyslog rsyslog-mmjsonparse rsyslog-elasticsearch -y
FILE=/etc/rsyslog.d/75-elastic.conf
grep "CDMCS" $FILE || cat >> $FILE <<'EOF'
# CDMCS
module(load="omelasticsearch")
module(load="mmjsonparse")

template(name="suricata-index" type="list") {
    constant(value="suricata-")
    property(name="timereported" dateFormat="rfc3339" position.from="1" position.to="4")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="6" position.to="7")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="9" position.to="10")
    constant(value=".")
    property(name="timereported" dateFormat="rfc3339" position.from="12" position.to="13")
}

template(name="JSON" type="list") {
    property(name="$!all-json")
}

if $syslogtag contains 'suricata' and $msg startswith ' @cee:' then {

  action(type="mmjsonparse")

  if $parsesuccess == "OK" then action(
    type="omelasticsearch"
    template="JSON"
    server="127.0.0.1"
    serverport="9200"
    searchIndex="suricata-index"
    dynSearchIndex="on"
  )

}
EOF

systemctl stop rsyslog.service
rsyslogd -N 1 || exit 1
check_service rsyslogd

# influx
echo "Provisioning INFLUXDB"
cd $PKGDIR
[[ -f $INFLUX ]] || wget $WGET_PARAMS https://dl.influxdata.com/influxdb/releases/$INFLUX -O $INFLUX
dpkg -s influxdb || dpkg -i $INFLUX > /dev/null 2>&1
systemctl stop influxdb.service
check_service influxdb

# grafana
echo "Provisioning GRAFANA"
cd $PKGDIR
[[ -f $GRAFANA ]] || wget $WGET_PARAMS https://s3-us-west-2.amazonaws.com/grafana-releases/release/$GRAFANA -O $GRAFANA
apt-get -y install libfontconfig > /dev/null 2>&1
dpkg -s grafana || dpkg -i $GRAFANA > /dev/null 2>&1
systemctl stop grafana-server.service
check_service grafana-server

sleep 5
curl -s -XPOST --user admin:admin $EXPOSE:3000/api/datasources -H "Content-Type: application/json" -d '{
    "name": "telegraf",
    "type": "influxdb",
    "access": "proxy",
    "url": "http://localhost:8086",
    "database": "telegraf",
    "isDefault": true
}'

# scirius
config_scirius(){
  cd /opt
  git clone https://github.com/StamusNetworks/scirius
  cd scirius && git checkout tags/scirius-3.1.0

  /usr/local/bin/virtualenv ./
  source $SCIRIUS_PATH/bin/activate

  pip install -r requirements.txt
  pip install --upgrade urllib3
  pip install gunicorn pyinotify python-daemon

  npm install -g npm@latest webpack@3.11
  npm install
  cd hunt
  npm install
  npm run build
  cd ..

  python manage.py migrate  --noinput
  echo "from django.contrib.auth.models import User; User.objects.create_superuser('vagrant', 'vagrant@localhost', 'vagrant')" | python manage.py shell
  chown www-data db.sqlite3
  chown -R www-data $SCIRIUS_PATH

  echo 'ELASTICSEARCH_LOGSTASH_INDEX = "suricata-"'  >> $SCIRIUS_CONF
  echo 'ELASTICSEARCH_LOGSTASH_ALERT_INDEX = "suricata-"'  >> $SCIRIUS_CONF
  echo 'ELASTICSEARCH_VERSION = 6'  >> $SCIRIUS_CONF
  echo 'ELASTICSEARCH_KEYWORD = "keyword"'  >> $SCIRIUS_CONF
  echo 'ELASTICSEARCH_LOGSTASH_TIMESTAMPING = "daily"'  >> $SCIRIUS_CONF
  echo "ALLOWED_HOSTS = [\"$EXPOSE\"]"  >> $SCIRIUS_CONF
  echo 'SURICATA_NAME_IS_HOSTNAME = True'  >> $SCIRIUS_CONF
  echo 'ELASTICSEARCH_HOSTNAME = "host"' >> $SCIRIUS_CONF
  echo 'USE_KIBANA = True' >> $SCIRIUS_CONF
  echo "KIBANA_URL = \"$EXPOSE:5601\"" >> $SCIRIUS_CONF
  echo 'KIBANA_INDEX = ".kibana"' >> $SCIRIUS_CONF
  echo "USE_EVEBOX = True" >> $SCIRIUS_CONF
  echo "EVEBOX_ADDRESS = \"$EXPOSE:5636\"" >> $SCIRIUS_CONF

  # adding sources to rulesets
  python $SCIRIUS_PATH/manage.py addsource "ETOpen Ruleset" https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz http sigs
  python $SCIRIUS_PATH/manage.py addsource "PT Research Ruleset" https://github.com/ptresearch/AttackDetection/raw/master/pt.rules.tar.gz http sigs
  python $SCIRIUS_PATH/manage.py addsource "CDMCS Custom Sigs" https://raw.githubusercontent.com/ccdcoe/CDMCS/master/Suricata/vagrant/singlehost/local.rules http sig
  python $SCIRIUS_PATH/manage.py defaultruleset "CDMCS ruleset"
  python $SCIRIUS_PATH/manage.py addsuricata suricata "Suricata on CDMCS" /etc/suricata/rules "CDMCS ruleset"
  python $SCIRIUS_PATH/manage.py updatesuricata
  python $SCIRIUS_PATH/suricata/scripts/suri_reloader -p /etc/suricata/rules  -l /var/log/suri-reload.log -D
  deactivate
  echo "1" > /var/log/vagrant-provisioned.log
}
echo "Provisioning SCIRIUS"
cd $PKGDIR
[[ -f $SCIRIUS ]] || wget $WGET_PARAMS http://packages.stamus-networks.com/selks4/debian/pool/main/s/scirius/$SCIRIUS -O $SCIRIUS

apt-get install -y nginx python-pip dbconfig-common sqlite3 npm > /dev/null
pip install --upgrade pip virtualenv #urllib3 chardet

#grep 1 /var/log/vagrant-provisioned.log || config_scirius
#dpkg -s scirius || dpkg -i $SCIRIUS > /dev/null 2>&1
#apt-get -f install -y

FILE=/etc/systemd/system/scirius.service
grep "scirius" $FILE || cat > $FILE <<EOF
[Unit]
Description=scirius daemon
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/scirius
ExecStart=/opt/scirius/bin/gunicorn --log-syslog -t 600 -w 4 --bind unix:/tmp/scirius.sock scirius.wsgi:application
Environment=VIRTUAL_ENV=/opt/scirius
Environment=PATH=$VIRTUAL_ENV/bin:$PATH

[Install]
WantedBy=multi-user.target
EOF
#check_service scirius

#systemctl stop nginx.service
#FILE=/etc/nginx/sites-available/scirius
#grep scirius $FILE || cat > $FILE <<'EOF'
#server {
#   listen 0.0.0.0:80;
#   access_log /var/log/nginx/scirius.access.log;
#   error_log /var/log/nginx/scirius.error.log;
#
#   #error_log syslog:server=unix:/dev/log,faility=local7,tag=nginx,severity=error;
#   #access_log syslog:server=unix:/dev/log,faility=local7,tag=nginx,severity=info main;
#
#   # https://docs.djangoproject.com/en/dev/howto/static-files/#serving-static-files-in-production
#   location /static/rules {
#       alias /opt/scirius/rules/static/rules/;
#       expires 30d;
#   }
#   location /static/js {
#       alias /opt/scirius/rules/static/js/;
#       expires 30d;
#   }
#   location /static/fonts {
#       alias /opt/scirius/rules/static/fonts/;
#       expires 30d;
#   }
#   location /static/django_tables2 {
#       alias /opt/scirius/lib/python2.7/site-packages/django_tables2/static/django_tables2/;
#       expires 30d;
#   }
#   location / {
#       proxy_pass http://unix:/tmp/scirius.sock:/;
#       proxy_read_timeout 600;
#       proxy_set_header Host $http_host;
#       proxy_redirect off;
#       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#   }
#}
#EOF
#[[ -f /etc/nginx/sites-enabled/scirius ]] || ln -s $FILE /etc/nginx/sites-enabled
#[[ -f /etc/nginx/sites-enabled/default ]] && rm /etc/nginx/sites-enabled/default
#check_service nginx

# evebox
echo "Provisioning EVEBOX"
if [[ $DOCKERIZE ]]; then
  docker ps -a | grep evebox || docker run -dit --name evebox -h evebox --network cdmcs --restart unless-stopped -p 5636:5636 --log-driver syslog --log-opt tag="evebox" $DOCKER_EVEBOX -e http://elastic:9200 --index suricata --elasticsearch-keyword keyword
else
  cd $PKGDIR
  [[ -f $EVEBOX ]] || wget $WGET_PARAMS https://evebox.org/files/release/latest/$EVEBOX -O $EVEBOX
  dpkg -i $EVEBOX > /dev/null 2>&1
  grep "suricata" /etc/default/evebox || echo 'ELASTICSEARCH_INDEX="suricata"' >> /etc/default/evebox
  systemctl stop evebox.service

  FILE=/etc/default/evebox
  grep "CDMCS" $FILE || cat > $FILE <<'EOF'
# CDMCS
#CONFIG="-c /etc/evebox/evebox.yaml"
ELASTICSEARCH_URL="-e http://localhost:9200"
EVEBOX_OPTS="--index suricata"
EOF

  check_service evebox
fi

# telegraf
echo "Provisioning TELEGRAF"
cd $PKGDIR
[[ -f $TELEGRAF ]] || wget $WGET_PARAMS https://dl.influxdata.com/telegraf/releases/$TELEGRAF -O $TELEGRAF
dpkg -i $TELEGRAF > /dev/null 2>&1

systemctl stop telegraf.service
FILE=/etc/telegraf/telegraf.conf
grep "CDMCS" $FILE || cat > $FILE <<EOF
[global_tags]
  year = "2018"

[agent]
  hostname = "CDMCS"
  omit_hostname = false
  interval = "1s"
  round_interval = true
  metric_buffer_limit = 1000
  flush_buffer_when_full = true
  collection_jitter = "0s"
  flush_interval = "60s"
  flush_jitter = "10s"
  debug = false
  quiet = true

[[outputs.influxdb]]
  database  = "telegraf"
  urls  = ["http://localhost:8086"]

[[inputs.cpu]]
  percpu = true
  totalcpu = true
[[inputs.disk]]
  ignore_fs = ["tmpfs", "devtmpfs"]
[[inputs.diskio]]
[[inputs.kernel]]
[[inputs.mem]]
[[inputs.net]]
[[inputs.netstat]]
[[inputs.processes]]
[[inputs.swap]]
[[inputs.system]]
EOF

check_service telegraf

echo "making some noise"
while : ; do curl -s https://www.facebook.com/ > /dev/null 2>&1 ; sleep 1 ; done &
while : ; do curl -s http://testmyids.com > /dev/null 2>&1 ; sleep 30 ; done &

sleep 5

netstat -anutp
curl -s -XPOST localhost:9200/suricata-*/_search -H "Content-Type: application/json" -d '
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "timestamp": {
              "gte": "now-1h",
              "lte": "now"
            }
          }
        }
      ]
    }
  },
  "aggs": {
    "events": {
      "terms": {
        "field": "event_type.keyword",
        "size": 20
      }
    },
    "alertTop10": {
      "terms": {
        "field": "alert.signature.keyword",
        "size": 10
      }
    }
  }
}
' | jq .
