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
  year=$(printf $pcap | cut -d "-" -f1)
  month=$(printf $pcap | cut -d "-" -f2)
  day=$(printf $pcap | cut -d "-" -f3)
  [[ -f ${pcap}.pcap.zip ]] || wget -O $ROOT/${pcap}.pcap.zip $WGET_PARAMS https://malware-traffic-analysis.net/${year}/${month}/${day}/${pcap}.pcap.zip
  unzip -n -P infected -d ${ROOT} ${ROOT}/${pcap}.pcap.zip
done
