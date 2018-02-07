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
