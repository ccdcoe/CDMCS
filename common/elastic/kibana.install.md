# install kibana

 * https://www.elastic.co/guide/en/kibana/current/deb.html
 * https://www.elastic.co/guide/en/kibana/current/_configuring_kibana_on_docker.html

## deb package

```bash
KIBANA="kibana-6.1.2-amd64.deb"
[[ -f $KIBANA ]] || wget $WGET_PARAMS https://artifacts.elastic.co/downloads/kibana/$KIBANA -O $KIBANA
dpkg -s kibana || dpkg -i $KIBANA > /dev/null 2>&1

systemctl stop kibana.service
systemctl start kibana.service

FILE=/etc/kibana/kibana.yml
grep "provisioned" $FILE || cat >> $FILE <<EOF
# provisioned
server.host: "0.0.0.0"
EOF
```
