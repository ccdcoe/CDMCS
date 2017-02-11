{% set os = grains.get('os')|lower %}
{% set influx_key = '2582E0C5' %}
{% set debian_apt_list = '/etc/apt/sources.list.d/influxdata.list' %}

{% if grains['os_family'] == 'Debian' %}
apt-transport-https:
  pkg.installed
tick_repo:
  pkgrepo.managed:
    - humanname: TICK stack repository from Influxdata
    - name: deb https://repos.influxdata.com/{{ os }} {{ grains['oscodename']}} stable
    - key_url: https://repos.influxdata.com/influxdb.key
    - file: /etc/apt/sources.list.d/influxdata.list
    - clean_file: True
{% elif grains['os_family'] == 'RedHat' %}
tick_repo:
  pkgrepo.managed:
    - humanname: TICK stack repository from Influxdata
    - gpgkey: https://repos.influxdata.com/influxdb.key
    - baseurl: https://repos.influxdata.com/centos/$releasever/$basearch/stable
    - gpgcheck: 1
{% endif %}

telegraf:
  pkg.latest:
    - refresh: True
    - require:
      - pkgrepo: tick_repo
  service.running:
    - name: telegraf
    - enable: True
    - watch:
      - file: /etc/telegraf/telegraf.conf
/etc/telegraf/telegraf.conf:
  file.managed:
    - source: salt://telegraf/conf.jinja
    - template: jinja
    - mode: 0644
    - default:
      url: influx
      database: telegraf
