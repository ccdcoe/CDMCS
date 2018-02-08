# create suricata drop rules

* Drop DNS queries for facebook
* Drop HTTP traffic on non-standard ports (e.g., HTTP on port 53)
  * Use test examples below, drop only initial GET response from `home_net -> external`
* Drop all HTTP GET requests directed at `detectportal.firefox.com`

## tips for testing

### use docker containers on host

```
docker run --rm -i --name apache-on-dns-port -p 53:80 -v "$PWD":/usr/local/apache2/htdocs/ httpd
sudo docker run --rm -ti -p 53:53/tcp -p 53:53/udp --cap-add=NET_ADMIN andyshinn/dnsmasq
```

### then test from client box

```
curl 192.168.10.1:53
dig A facebook.com @192.168.10.1 -p 53
```
