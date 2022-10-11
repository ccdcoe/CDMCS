#!/bin/bash

exit_with_message() {
  printf "%s\n" "$1"
  exit 1
}

which unzip || exit_with_message "please install unzip"

WGET_PARAMS="-4 -q"
ROOT=$(dirname "$0")

for pcap in $(cat ${ROOT}/source-mta-pcap.txt) ; do
  echo pulling $pcap
  file=$(printf $pcap | cut -d "/" -f7)
  [[ -f $ROOT/${file} ]] || wget -O $ROOT/${file} $WGET_PARAMS ${pcap}
  unzip -n -P infected -d ${ROOT} ${ROOT}/${file}
done
