/etc/systemd/system/moloch-wise.service:
  file.managed:
    - mode: 644
    - source: salt://moloch/files/molochwise.systemd.service
    - template: jinja
    - default:
      dir: /data/moloch

moloch_wise_add_init:
  cmd.run:
    - name: systemctl daemon-reload
    - unless: systemctl list-units | grep wise

/data/moloch/etc/wise.ini:
  file.managed:
    - mode: 644
    - source: salt://moloch/files/wise.ini
    - template: jinja

moloch-wise:
  service.running:
    - enable: True
    - require:
      - file: /etc/systemd/system/moloch-wise.service
      - file: /data/moloch/etc/wise.ini
    - watch:
      - /data/moloch/etc/wise.ini
