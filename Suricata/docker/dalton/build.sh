#!/usr/bin/env bash

export debian_frontend=noninteractive
export port=8089

bash stop.sh

echo "provisioning dalton"
[[ -d dalton ]] || git clone https://github.com/secureworks/dalton.git
cd dalton && grep $port .env || sed -i "s/DALTON_EXTERNAL_PORT=80/DALTON_EXTERNAL_PORT=$port/g" .env

if [ -f "/etc/arch-release" ]; then
  sudo bash -c "time docker-compose build && docker-compose up -d"
else
  time docker-compose build && docker-compose up -d
fi
