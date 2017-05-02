{% set vars = pillar.elasticsearch.config %}
{% set ip = grains.ipv4[2] %}

{% do vars['network'].update({
  'host':ip
}) %}

/etc/elasticsearch/jvm.options:
  file.managed:
    - mode: 644
    - source: salt://elasticsearch/files/jvm.options
    - template: jinja

/etc/elasticsearch/elasticsearch.yml:
  file.serialize:
    - mode: 644
    - dataset: {{ vars }}
    - formatter: yaml
