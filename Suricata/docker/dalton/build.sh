#!/usr/bin/env bash

export DEBIAN_FRONTEND=noninteractive

echo "Provisioning DALTON"
[[ -d dalton ]] || git clone https://github.com/secureworks/dalton.git
cd dalton && sed -i 's/DALTON_EXTERNAL_PORT=80/DALTON_EXTERNAL_PORT=8087/g' .env

if [ -f "/etc/arch-release" ]; then
  sudo bash -c "time docker-compose build && docker-compose up -d"
else
  time docker-compose build && docker-compose up -d
fi
