# run

 * **[find](https://linux.die.net/man/1/find) is your friend**

## basic execution

```
cd <scirius install dir>

source bin/activate
python manage.py runserver 0.0.0.0:8000

```

## gunicorn + nginx

 * https://docs.djangoproject.com/en/dev/howto/static-files/#serving-static-files-in-production
 * https://www.digitalocean.com/community/tutorials/how-to-set-up-django-with-postgres-nginx-and-gunicorn-on-ubuntu-16-04

```
gunicorn --log-syslog -t 600 -w 4 --bind unix:/tmp/scirius.sock scirius.wsgi:application
```
```
server {
   listen 0.0.0.0:80;
   access_log /var/log/nginx/scirius.access.log;
   error_log /var/log/nginx/scirius.error.log;

   location /static/rules {
       alias /var/lib/scirius/static/rules/;
       expires 30d;
   }
   location /static/js {
       alias /var/lib/scirius/static/js/;
       expires 30d;
   }
   location /static/fonts {
       alias /var/lib/scirius/static/fonts/;
       expires 30d;
   }
   location /static/django_tables2 {
       alias /var/lib/scirius/static/django_tables2/;
       expires 30d;
   }
   location / {
       proxy_pass http://unix:/tmp/scirius.sock:/;
       proxy_read_timeout 600;
       proxy_set_header Host $http_host;
       proxy_redirect off;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   }
}
```

### testing config

```
nginx -t -c /etc/nginx/nginx.conf
```
