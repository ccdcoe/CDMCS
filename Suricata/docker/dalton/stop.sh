#!/usr/bin/env bash

echo "stopping dalton"
[[ -d dalton ]] || exit 1
cd dalton 

if [ -f "/etc/arch-release" ]; then
  sudo bash -c "docker-compose stop && docker-compose rm -f"
else
  time docker-compose stop && docker-compose rm -f
fi

