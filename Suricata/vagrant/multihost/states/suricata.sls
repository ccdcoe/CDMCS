{% set conf = '/etc/suricata/suricata.yaml' %}
{% set params = '/etc/default/suricata' %}
{% set ruleFile = '/var/lib/suricata/rules/suricata.rules'%}

include:
  - ethtool

python-pip:
  pkg.installed

suricata-update:
  pip.installed:
    - require:
      - pkg: python-pip

suricata:
  pkgrepo.managed:
    - humanname: OISF suricata stable repository
    - ppa: oisf/suricata-stable
  pkg.latest:
    - refresh: True
    - pkgs:
      - libhtp1
      - suricata
  service.running:
    - name: suricata
    - enable: True
    - watch:
      - {{ conf }}
      - {{ params }}

{{ conf }}:
  file.managed:
    - mode: 644
    - source: salt://fileserver/suricata.jinja
    - template: jinja
    - default:
      interface: "enp0s3"
      rulefile: {{ ruleFile }}

{{ params }}:
  file.managed:
    - mode: 644
    - source: salt://fileserver/default.conf


suricata-update enable-source et/open:
  cmd.run:
    - unless: suricata-update list-enabled-sources | grep "et/open"
    - require:
      - pkg: suricata

{{ ruleFile }}:
  file.managed

suricata-update update:
  cmd.run:
    - require:
      - pkg: suricata
      - pip: suricata-update

suricatasc -c "reload-rules":
  cmd.run:
    - onchanges: 
      - cmd: suricata-update update
