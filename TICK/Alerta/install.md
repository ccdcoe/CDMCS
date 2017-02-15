# Installing Alerta on Debian | Ubuntu

see :
* http://alerta.readthedocs.io/en/latest/quick-start.html
* http://alerta.readthedocs.io/en/latest/deployment.html#web-proxy

```
apt-get -y install mongodb libffi-dev python-pip
pip install --upgrade pip
pip install alerta-server alerta
cat > /etc/alertad.conf <<EOF
CORS_ORIGINS = [
    'http://INSERT_YOUR_IP_HERE'
]
EOF

apt-get -y install nginx
cd /var/www/html/
wget -q -4 -O alerta-web.tgz https://github.com/alerta/angular-alerta-webui/tarball/master
tar zxvf alerta-web.tgz
ALERTA=$(file alerta-angular-alerta-webui-* | head -1 | cut -f1 -d:)
ln -s $ALERTA alerta

cat > /etc/nginx/sites-enabled/alerta <<EOF
upstream backend {
        server localhost:8080 fail_timeout=0;
}
server {
        listen 80 default_server deferred;
        location /api/ {
                proxy_pass http://backend/;
                proxy_set_header Host \$host:\$server_port;
                proxy_set_header X-Real-IP \$remote_addr;
                proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
        location / {
                root /var/www/html/alerta/app;
        }
}
EOF

rm /etc/nginx/sites-enabled/default
service nginx reload

# Quick way of running alertad
nohup alertad 2>&1 > /var/log/alerta.log &

```

By defaul configuration file is located at */etc/alertad.conf*

By default Alerta server will:
* log to /std/out & /std/err
* use mongoDB database
* have initial username and password ?
* listen to the port 8080

-----
-> Next [sending some alerts](sendAlert2Alerta.md)
