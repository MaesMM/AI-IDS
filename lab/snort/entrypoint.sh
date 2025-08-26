#!/bin/bash
ip link set eth0 promisc on 
mkdir sharedVol
ln -s /usr/local/snort/etc/snort/docker-volume sharedVol
(/usr/local/snort/bin/snort -c /usr/local/snort/etc/snort/snort.lua -l /var/log/snort --daq-dir /usr/local/lib/daq_s3/lib/daq -i eth0 -A csv) &
exec /bin/bash