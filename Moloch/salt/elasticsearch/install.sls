apt-transport-https:
  pkg.latest

elasticsearch-repo:
  pkgrepo.managed:
    - humanname: Elasticsearch repository
    - name: deb https://artifacts.elastic.co/packages/5.x/apt stable main
    - key_url: https://artifacts.elastic.co/GPG-KEY-elasticsearch
    - file: /etc/apt/sources.list.d/elasticsearch.list
    - clean_file: True

elasticsearch:
  pkg.latest:
    - require:
      - pkgrepo: elasticsearch-repo
  service.running:
    - enable: True
    - require:
      - pkg: elasticsearch
    - watch:
      - file: /etc/elasticsearch/jvm.options
      - file: /etc/elasticsearch/elasticsearch.yml
