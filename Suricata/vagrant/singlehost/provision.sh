check_service(){
  systemctl daemon-reload
  systemctl is-enabled $1.service 2>/dev/null | grep "disabled" && systemctl enable $1.service
  systemctl status $1.service | egrep  "inactive|failed" && systemctl start $1.service
  systemctl status $1.service
}

# params
DEBUG=true
PROXY=http://192.168.10.1:3128
PKGDIR=/vagrant/pkgs
WGET_PARAMS="-4 -q"

# versions
ELA="elasticsearch-6.1.1.deb"
KIBANA="kibana-6.1.1-amd64.deb"
LOGSTASH="logstash-6.1.1.deb"
INFLUX="influxdb_1.4.2_amd64.deb"
TELEGRAF="telegraf_1.5.0-1_amd64.deb"
GRAFANA="grafana_4.6.3_amd64.deb"
EVEBOX="evebox_0.8.1_amd64.deb"

# for deb
SCIRIUS="scirius_1.2.7-1_amd64.deb"
# for git
SCIRIUS_PATH="/opt/scirius"
SCIRIUS_CONF=$SCIRIUS_PATH/scirius/local_settings.py

start=$(date)

# basic OS config
FILE=/etc/sysctl.conf
grep "disable_ipv6" $FILE || cat >> $FILE <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p

# no persistent storage, only use as mem cache
docker run -dit --restart unless-stopped -p 127.0.0.1:6379:6379 redis

#FILE=/etc/profile
#grep "proxy" $FILE || cat >> $FILE <<EOF
#http_proxy=$PROXY
#https_proxy=$PROXY
#export http_proxy
#export https_proxy
#EOF
#source /etc/profile

FILE=/etc/apt/apt.conf.d/99force-ipv4
[[ -f $FILE ]] ||  echo 'Acquire::ForceIPv4 "true";' | sudo tee $FILE
export DEBIAN_FRONTEND=noninteractive
mkdir -p /vagrant/pkgs

#cd /tmp && rm -f snoopy-install.sh && wget -O snoopy-install.sh https://github.com/a2o/snoopy/raw/install/doc/install/bin/snoopy-install.sh && chmod 755 snoopy-install.sh && ./snoopy-install.sh stable

# basic software
apt-get update > /dev/null && apt-get install -y curl htop vim tmux > /dev/null

# suricata
install_suricata_from_ppa(){
  add-apt-repository ppa:oisf/suricata-stable > /dev/null 2>&1 \
  && apt-get update > /dev/null \
  && apt-get install -y suricata > /dev/null
}
echo "Provisioning SURICATA"
suricata -V || install_suricata_from_ppa

[[ -f /etc/suricata/rules/scirius.rules ]] || touch /etc/suricata/rules/scirius.rules
if $DEBUG ; then ip addr show; fi
systemctl stop suricata

if $DEBUG ; then suricata -T || exit 1 ; fi
touch  /etc/suricata/threshold.config

FILE=/etc/suricata/suricata.yaml
grep "cdmcs" $FILE || cat >> $FILE <<EOF
include: cdmcs-detect.yaml
include: cdmcs-logging.yaml
EOF

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
default-rule-path: /etc/suricata/rules
rule-files:
 - scirius.rules
sensor-name: CDMCS
EOF

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
            metadata: yes              # add L7/applayer fields, flowbit and other vars to the alert
            tagged-packets: yes
            xff:
              enabled: no
              mode: extra-data
              deployment: reverse
              header: X-Forwarded-For
        - http:
            extended: yes     # enable this for extended logging information
        - dns:
            query: yes     # enable logging of DNS queries
            answer: yes    # enable logging of DNS answers
        - tls:
            extended: yes     # enable this for extended logging information
        - files:
            force-magic: no   # force logging magic on all logged files
        - smtp:
        - ssh
        - stats:
            totals: yes       # stats for all threads merged together
            threads: no       # per thread stats
            deltas: no        # include delta values
        - flow
EOF

#if $DEBUG ; then suricata -T -vvv; fi

check_service suricata
#check_service suri-reloader

# java
install_oracle_java() {
  echo "Installing oracle Java"
  echo 'oracle-java8-installer shared/accepted-oracle-license-v1-1 boolean true' | debconf-set-selections \
  && add-apt-repository ppa:webupd8team/java \
  && apt-get update > /dev/null \
  && apt-get -y install oracle-java8-installer > /dev/null
}
echo "Provisioning JAVA"
# https://askubuntu.com/questions/966107/cant-install-oracle-java-8-in-ubuntu-16-04
# java -version || install_oracle_java
#apt-get update
apt-get install -y openjdk-8-jre-headless

# elastic
echo "Provisioning ELASTICSEARCH"
cd $PKGDIR
[[ -f $ELA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/elasticsearch/$ELA -O $ELA
dpkg -s elasticsearch || dpkg -i $ELA > /dev/null 2>&1

check_service elasticsearch

# kibana
echo "Provisioning KIBANA"
cd $PKGDIR
[[ -f $KIBANA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/kibana/$KIBANA -O $KIBANA
dpkg -s kibana || dpkg -i $KIBANA > /dev/null 2>&1

FILE=/etc/kibana/kibana.yml
grep "provisioned" $FILE || cat >> $FILE <<EOF
# provisioned
server.host: "0.0.0.0"
EOF

check_service kibana

# set up default index pattern
sleep 5
#curl -ss -XPUT localhost:9200/.kibana/index-pattern/a1571060-e8e2-11e7-9cf4-db76e233e72b -d @/vagrant/kibana-index-pattern.json -H'Content-Type: application/json'
#curl -ss -XPUT localhost:9200/.kibana/config/5.6.2 -d @/vagrant/kibana-index-pattern-config.json -H'Content-Type: application/json'

# logstash
echo "Provisioning LOGSTASH"
cd $PKGDIR
[[ -f $LOGSTASH ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/logstash/$LOGSTASH -O $LOGSTASH
dpkg -s logstash || dpkg -i $LOGSTASH > /dev/null 2>&1

FILE=/etc/logstash/conf.d/suricata.conf
grep "CDMCS" $FILE || cat >> $FILE <<EOF
input {
  file {
    path => "/var/log/suricata/eve.json"
    tags => ["suricata", "CDMCS", "fromfile"]
  }
  redis {
    data_type => "list"
    host => "127.0.0.1"
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
    hosts => ["localhost"]
    index => "suricata-%{+YYYY.MM.dd.hh}"
  }
}
EOF
curl -ss -XPUT localhost:9200/_template/default -d @/vagrant/elastic-default-template.json -H'Content-Type: application/json'
chown root:logstash /var/log/suricata/eve.json

/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/suricata.conf -t || exit 1

check_service logstash



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

sleep 1
curl -s -XPOST --user admin:admin 192.168.10.11:3000/api/datasources -H "Content-Type: application/json" -d '{
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
  cd scirius

  /usr/local/bin/virtualenv ./
  source $SCIRIUS_PATH/bin/activate

  pip install -r requirements.txt
  pip install --upgrade urllib3
  pip install gunicorn pyinotify python-daemon
  python manage.py syncdb  --noinput
  echo "from django.contrib.auth.models import User; User.objects.create_superuser('vagrant', 'vagrant@localhost', 'vagrant')" | python manage.py shell
  chown www-data db.sqlite3
  chown www-data $SCIRIUS_PATH

  echo 'ELASTICSEARCH_LOGSTASH_INDEX = "suricata-"'  >> $SCIRIUS_CONF
  echo 'ELASTICSEARCH_LOGSTASH_ALERT_INDEX = "suricata-"'  >> $SCIRIUS_CONF
  echo 'ELASTICSEARCH_VERSION = 6'  >> $SCIRIUS_CONF
  echo 'ELASTICSEARCH_KEYWORD = "keyword"'  >> $SCIRIUS_CONF
  echo 'ELASTICSEARCH_LOGSTASH_TIMESTAMPING = "daily"'  >> $SCIRIUS_CONF
  echo 'ALLOWED_HOSTS = ["192.168.10.11"]'  >> $SCIRIUS_CONF
  echo 'SURICATA_NAME_IS_HOSTNAME = True'  >> $SCIRIUS_CONF
  echo 'ELASTICSEARCH_HOSTNAME = "host"' >> $SCIRIUS_CONF

  # adding sources to rulesets
  python $SCIRIUS_PATH/manage.py addsource "ETOpen Ruleset" https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz http sigs
  python $SCIRIUS_PATH/manage.py addsource "PT Research Ruleset" https://github.com/ptresearch/AttackDetection/raw/master/pt.rules.tar.gz http sigs
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

apt-get install -y nginx python-pip dbconfig-common sqlite3 > /dev/null
pip install --upgrade pip virtualenv #urllib3 chardet

grep 1 /var/log/vagrant-provisioned.log || config_scirius
#dpkg -s scirius || dpkg -i $SCIRIUS > /dev/null 2>&1

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
check_service scirius

systemctl stop nginx.service
FILE=/etc/nginx/sites-available/scirius
grep scirius $FILE || cat > $FILE <<'EOF'
server {
   listen 192.168.10.11:80;
   access_log /var/log/nginx/scirius.access.log;
   error_log /var/log/nginx/scirius.error.log;

   #error_log syslog:server=unix:/dev/log,faility=local7,tag=nginx,severity=error;
   #access_log syslog:server=unix:/dev/log,faility=local7,tag=nginx,severity=info main;

   # https://docs.djangoproject.com/en/dev/howto/static-files/#serving-static-files-in-production
   location /static/rules {
       alias /opt/scirius/rules/static/rules/;
       expires 30d;
   }
   location /static/js {
       alias /opt/scirius/rules/static/js/;
       expires 30d;
   }
   location /static/fonts {
       alias /opt/scirius/rules/static/fonts/;
       expires 30d;
   }
   location /static/django_tables2 {
       alias /opt/scirius/lib/python2.7/site-packages/django_tables2/static/django_tables2/;
       expires 30d;
   }
   location / {
       proxy_pass http://unix:/tmp/scirius.sock:/;
       proxy_read_timeout 600;
       proxy_set_header Host $http_host;
       proxy_redirect off;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   }
}
EOF
[[ -f /etc/nginx/sites-enabled/scirius ]] || ln -s $FILE /etc/nginx/sites-enabled
[[ -f /etc/nginx/sites-enabled/default ]] && rm /etc/nginx/sites-enabled/default

check_service nginx

# evebox
echo "Provisioning EVEBOX"
cd $PKGDIR
[[ -f $EVEBOX ]] || wget $WGET_PARAMS https://evebox.org/files/release/latest/evebox_0.8.1_amd64.deb -O $EVEBOX
dpkg -i $TELEGRAF > /dev/null 2>&1

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

systemctl status suricata.service | grep 'running' || echo "SURICATA DOWN"
systemctl status scirius.service | grep 'running' || echo "SCIRIUS DOWN"
systemctl status nginx.service | grep 'running' || echo "NGINX DOWN"
#netstat -anutp
