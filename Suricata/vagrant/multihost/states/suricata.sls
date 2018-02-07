{% set conf = '/etc/suricata/suricata.yaml' %}
{% set params = '/etc/default/suricata' %}

include:
  - ethtool

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
      home_net: "10.0.0.0/8"
      interface: "enp0s3"

{{ params }}:
  file.managed:
    - mode: 644
    - source: salt://fileserver/default.conf
