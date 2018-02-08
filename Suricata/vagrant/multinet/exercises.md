# create suricata drop rules

* Drop HTTP traffic on non-standard ports (e.g., HTTP on port 53)
* 

## tips for testing

* use docker

```
docker run --rm -i --name apache-on-dns-port -p 53:80 -v "$PWD":/usr/local/apache2/htdocs/ httpd
```
