/data/moloch/etc/config.ini:
  file.managed:
    - mode: 644
    - source: salt://moloch/files/config.ini
    - template: jinja
    - default:
      interface: {{ pillar['fpc'][grains.fqdn] }}

