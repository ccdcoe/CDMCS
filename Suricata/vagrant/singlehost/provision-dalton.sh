#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

echo "Provisioning DALTON"
apt-get install -y docker-compose > /dev/null 2>&1

cd /opt
[[ -d dalton ]] || git clone https://github.com/secureworks/dalton.git
cd dalton && sed -i 's/DALTON_EXTERNAL_PORT=80/DALTON_EXTERNAL_PORT=8087/g' .env
docker-compose build && docker-compose up -d
