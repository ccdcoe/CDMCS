moloch_create_db:
  cmd.run:
    - cwd: /data/moloch/db
    - shell: /bin/bash
    - name: ./db.pl localhost:9200 init
    - onlyif: ./db.pl localhost\:9200 info | grep "DB Version" | grep -1
moloch_create_user:
  cmd.run:
    - cwd: /data/moloch/viewer
    - shell: /bin/bash
    - name: /data/moloch/bin/node addUser.js -c ../etc/config.ini admin "Admin" admin -admin
    - unless: curl -ss -XGET localhost\:9200/users_v3/user/admin?pretty | python3 -c "import sys, json; es = json.load(sys.stdin); sys.exit(1) if es['found'] == False else None"
