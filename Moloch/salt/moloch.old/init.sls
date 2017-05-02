{% set vars = pillar['moloch'] %}
include:
  {% if grains['virtual'] == 'VMware' %}
  - datalvm
  {% endif %}
  - elasticsearch
  - nodejs
  - ethtool

deps:
  pkg.latest:
    - pkgs:
      - wget
      - curl
      - libpcre3-dev
      - uuid-dev
      - libmagic-dev
      - pkg-config
      - g++
      - flex
      - bison
      - zlib1g-dev
      - libffi-dev
      - gettext
      - libgeoip-dev
      - make
      - libjson-perl
      - libbz2-dev
      - libwww-perl
      - libpng-dev
      - xz-utils
      - libffi-dev

{{vars['user']}}:
  user.present:
    - fullname: Moloch daemon user
    - shell: /bin/false
    - home: {{vars['pcap_dir']}}

{{vars['pcap_dir']}}:   
  {% if grains['virtual'] == 'VMware' %}
  mount.mounted:
    - device: /dev/DATA/MAIN
    - fstype: ext4
    - persist: True
    - mkmnt: True
  {% endif %}
  file.directory:
    - user: {{vars['user']}}
    - group: {{vars['user']}}
    - dir_mode: 750
    - recurse:
      - user
      - group

{{vars['build_dir']}}:
  file.directory:
    - makedirs: True
  git.latest:
    - target: {{vars['build_dir']}}
    - name: https://github.com/aol/moloch
    - require:
      - pkg: basic.packages
moloch_build:
  cmd.run:
    - cwd: {{vars['build_dir']}}
    - shell: /bin/bash
    #- name: ./easybutton-build.sh -d {{vars['deploy_dir']}} && git rev-parse HEAD > {{vars['build_dir']}}/build.txt 
    - name: ./easybutton-build.sh -d {{vars['deploy_dir']}} && echo 1 > {{vars['build_dir']}}/build.txt 
    - unless: grep 1 {{vars['build_dir']}}/build.txt

moloch_deploy:
  cmd.run:
    - cwd: {{vars['build_dir']}}
    - shell: /bin/bash
    - name: make install && echo 1 > {{vars['build_dir']}}/deploy.txt 
    - unless: grep 1 {{vars['build_dir']}}/deploy.txt

{{vars['deploy_dir']}}/etc:
  file.directory

{{vars['deploy_dir']}}/etc/config.ini:
  file.managed:
    - source: salt://moloch/config.jinja
    - template: jinja
    - mode: 644

{% for file in ['GeoIP.dat', 'GeoIPASNum.dat', 'ipv4-address-space.csv' ] %}

{{vars['deploy_dir']}}/etc/{{file}}:
  file.managed:
    - source: salt://moloch/geoip/{{file}}
    - mode: 644
{% endfor %}

moloch_create_db:
  cmd.run:
    - cwd: {{vars['deploy_dir']}}/db
    - shell: /bin/bash
    - name: ./db.pl localhost:9200 init
    - onlyif: ./db.pl localhost\:9200 info | grep "DB Version" | grep -1
moloch_create_user:
  cmd.run:
    - cwd: {{vars['deploy_dir']}}/viewer
    - shell: /bin/bash
    - name: node addUser.js -c ../etc/config.ini admin "Admin" admin -admin
    - unless: curl -ss -XGET localhost\:9200/users_v3/user/admin?pretty | python3 -c "import sys, json; es = json.load(sys.stdin); sys.exit(1) if es['found'] == False else None"

{% if grains['init'] == 'upstart' %}
{% for file in ['capture', 'viewer'] %}
/etc/init/moloch-{{file}}.conf:
  file.managed:
    - source: salt://moloch/upstart/{{file}}.jinja
    - mode: 644
    - template: jinja
moloch_{{file}}_add_init:
  cmd.run:
    - name: initctl reload-configuration
    - unless: initctl list | grep moloch-{{file}}
{% endfor %}
{% elif grains['init'] == 'systemd' %}
{% for file in ['capture', 'viewer'] %}
/etc/systemd/system/moloch-{{file}}.service:
  file.managed:
    - source: salt://moloch/systemd/{{file}}.jinja
    - mode: 644
    - template: jinja
moloch_{{file}}_add_init:
  cmd.run:
    - name: systemctl daemon-reload
    - unless: systemctl list-units | grep moloch-{{file}}
{% endfor %}
{% endif %}

{% if vars['manage_capture_service'] == True %}
{% endif %}
moloch-capture:
  service.running:
    - enable: True
    - watch:
      - {{vars['deploy_dir']}}/etc/config.ini
      - {{vars['deploy_dir']}}/etc/GeoIP.dat
      - {{vars['deploy_dir']}}/etc/GeoIPASNum.dat
      - {{vars['deploy_dir']}}/etc/ipv4-address-space.csv
{% if vars['manage_viewer_service'] == True %}
moloch-viewer:
  service.running:
    - enable: True
    - watch:
      - {{vars['deploy_dir']}}/etc/config.ini
      - {{vars['deploy_dir']}}/etc/GeoIP.dat
      - {{vars['deploy_dir']}}/etc/GeoIPASNum.dat
      - {{vars['deploy_dir']}}/etc/ipv4-address-space.csv
{% endif %}

