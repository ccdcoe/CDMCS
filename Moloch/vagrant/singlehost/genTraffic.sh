#!/bin/bash

if [[ ! -f /var/run/generator-2 ]]; then
  echo "making some noise"
  while : ; do curl -s https://www.facebook.com/ > /dev/null 2>&1 ; sleep 30 ; done & sleep 1; echo $! > /var/run/generator-1
  while : ; do curl -s http://testmyids.com > /dev/null 2>&1 ; sleep 30 ; done & sleep 1; echo $! > /var/run/generator-2
fi
