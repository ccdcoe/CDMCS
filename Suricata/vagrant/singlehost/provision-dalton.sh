#!/bin/bash

echo "Provisioning DALTON"
cd /opt
[[ -d dalton ]] || git clone https://github.com/secureworks/dalton.git

apt-get install -f docker-compose

cd dalton && sed -i 's/DALTON_EXTERNAL_PORT=80/DALTON_EXTERNAL_PORT=8087/g' .env
docker-compose build && docker-compose up -d
