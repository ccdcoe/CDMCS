common:
  file.managed:
    - name: /tmp/1

after:
  cmd.run:
    - name: echo after
    - onchanges:
      - file: /tmp/1
