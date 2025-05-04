#!/bin/bash
cd /usr/local/src/libml/examples/classifier
python3 -m venv venv
source venv/bin/activate    
pip install scapy
python3 pcapgen.py

#lance snort avec la sortie dans la console
/usr/local/snort/bin/snort -c /usr/local/snort/etc/snort/snort.lua -i eth0 --daq-dir /usr/local/lib/daq_s3/lib/daq --warn-all