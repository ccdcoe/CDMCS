# SSL

```
mkdir -p /etc/nginx/ssl/
openssl req -new -nodes -x509 -subj "/C=FR/ST=IDF/L=Paris/O=Stamus/CN=SCIRIUS" -days 3650 -keyout /etc/nginx/ssl/scirius.key -out /etc/nginx/ssl/scirius.crt -extensions v3_ca
```
