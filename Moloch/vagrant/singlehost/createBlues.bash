#!/bin/bash

cd /data/moloch/viewer
for T in $(seq -w 1 22); do
  P=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)
  echo ${T} ${P}
  ../bin/node addUser.js "blue${T}" "Blue${T}" "${P}" --expression "country.src==${T}"
  echo "${P}" > blue${T}.pwd
done
