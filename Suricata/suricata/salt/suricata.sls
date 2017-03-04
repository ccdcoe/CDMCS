{% set pkg = 'suricata' %}
{% set conf = '/etc/suricata/suricata.yaml' %}
{% set params = '/etc/default/suricata' %}

include:
  - ethtool

{{pkg}}:
  pkgrepo.managed:
    - humanname: OISF suricata stable repository
    - clean_file: True
    {% if grains['os'] == 'Ubuntu' %}
    - ppa: oisf/suricata-stable
    {% elif grains['os'] == 'jessie' %}
    - name: deb http://ppa.launchpad.net/oisf/suricata-stable/ubuntu vivid main
    - file: /etc/apt/sources.list.d/oisf-suricata-stable-trusty.list
    - keyserver: keyserver.ubuntu.com
    - keyid: 9F6FC9DDB1324714B78062CBD7F87B2966EB736F
    {% endif %}
  pkg.latest:
    - refresh: True
    - pkgs:
      - libhtp1
      - {{pkg}}
  service.running:
    - name: {{pkg}}
    - enable: True
    - watch:
      - {{conf}}
      - {{params}}

{{conf}}:
  file.managed:
    - mode: 644
    - source: salt://files/suricata.jinja
    - template: jinja
    - default:
      home_net: "192.168.0.0/24,10.0.0.0/8"
      interface: "eth0"


{{params}}:
  file.managed:
    - mode: 644
    - source: salt://files/default.conf
