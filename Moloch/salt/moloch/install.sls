moloch:
  pkg.installed:
    - sources:
      - moloch: http://files.molo.ch/builds/ubuntu-16.04/moloch_0.18.2-1_amd64.deb
  user.present:
    - fullname: Moloch daemon user
    - shell: /bin/false
    - home: /srv/pcap
    - createhome: True

moloch_update_geo:
  cmd.run:
    - name: /data/moloch/bin/moloch_update_geo.sh
    - onchanges:
      - pkg: moloch
