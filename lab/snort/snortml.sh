#!/bin/bash

MODEL="/usr/local/snort/etc/snort/docker-volume/snort-http-classifier.model "
PCAP="/usr/local/snort/etc/snort/docker-volume/simulated_sql_injection.pcap"

usage() {
  echo "Usage: $0 [-m MODEL] [-p PCAP]"
  echo "  -m MODEL: path to the model file (default: $MODEL)"
  echo "  -p PCAP: path to the pcap file (default: $PCAP)"
  exit 1
}

while getopts ":m:p:" opt; do
  case $opt in
    m) MODEL="$OPTARG";;
    p) PCAP="$OPTARG";;
    \?) usage;;
  esac
done

shift $((OPTIND-1))

snort -c /usr/local/snort/etc/snort/snort.lua --talos --lua "snort_ml_engine = { http_param_model = \"$MODEL\" }; snort_ml = {}; trace = { modules = { snort_ml = {all = 1} } };" -r "$PCAP"
