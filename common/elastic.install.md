# install elasticsearch

```bash

ELASTICSEARCH="elasticsearch-5.2.1.deb"

apt-get -y install openjdk-8-jre-headless 

[[ -f $ELASTICSEARCH ]] || wget  -4 https://artifacts.elastic.co/downloads/elasticsearch/$ELASTICSEARCH
dpkg -i $ELASTICSEARCH 
systemctl enable elasticsearch 
systemctl start elasticsearch



```
