{% set interfaces = grains.ip4_interfaces %}
ethtool:
  pkg.installed

{% for interface, addr in interfaces.iteritems() %}
{{interface}}_gro_off:
  cmd.run:
    - name: /sbin/ethtool -K {{interface}} gro off
    - unless: /sbin/ethtool -k {{interface}} | grep generic-receive-offload | egrep '(off|on \[fixed\])'
{{interface}}_rxvlan_off:
  cmd.run:
    - name: /sbin/ethtool -K {{interface}} rxvlan off
    - unless: /sbin/ethtool -k {{interface}} | grep rx-vlan-offload | egrep '(off|on \[fixed\])'
{{interface}}_gso_off:
  cmd.run:
    - name: /sbin/ethtool -K {{interface}} gso off
    - unless: /sbin/ethtool -k {{interface}} | grep generic-segmentation-offload | egrep '(off|on \[fixed\])'
{{interface}}_sg_off:
  cmd.run:
    - name: /sbin/ethtool -K {{interface}} sg off
    - unless: /sbin/ethtool -k {{interface}} | grep tcp-segmentation-offload | egrep '(off|on \[fixed\])'
{{interface}}_rx_off:
  cmd.run:
    - name: /sbin/ethtool -K {{interface}} rx off
    - unless: /sbin/ethtool -k {{interface}} | grep rx-checksumming | egrep '(off|on \[fixed\])'
{{interface}}_up:
  cmd.run:
    - name: /sbin/ifconfig {{interface}} up
    - unless: /sbin/ifconfig {{interface}} | grep 'UP'
{% endfor %}
