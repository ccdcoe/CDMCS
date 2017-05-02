# Initially from:
# https://gist.github.com/renoirb/6722890

{% set os = grains.get('os')|lower %}
{% if os == 'ubuntu' %}
  {% set codename = grains.get('oscodename') %}
{% elif os == 'debian' %}
  {% set os = 'ubuntu' %}
  {% if grains['oscodename'] == 'jessie' %}
    {% set codename = 'xenial' %}
  {% elif grains['oscodename'] == 'wheezy' %}
    {% set codename = 'trusty' %}
  {% endif%}
{% endif %}

webupd8-repo:
  pkgrepo.managed:
    - humanname: WebUpd8 Oracle Java PPA repository
    - name: deb http://ppa.launchpad.net/webupd8team/java/{{os}} {{codename}} main
    - keyserver: keyserver.ubuntu.com
    - keyid: EEA14886
    - file: /etc/apt/sources.list.d/WebUpd8.list
    - clean_file: True

oracle-license-select:
  cmd.run:
    - unless: which java
    - name: '/bin/echo /usr/bin/debconf shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections'
    - require_in:
      - pkg: oracle-java8-installer
      - cmd: oracle-license-seen-lie

oracle-license-seen-lie:
  cmd.run:
    - name: '/bin/echo /usr/bin/debconf shared/accepted-oracle-license-v1-1 seen true  | /usr/bin/debconf-set-selections'
    - require_in:
      - pkg: oracle-java8-installer

oracle-java8-installer:
  pkg:
    - installed
    - require:
      - pkgrepo: webupd8-repo
