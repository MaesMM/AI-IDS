#!/bin/bash
cd /usr/local/src/libml/examples/classifier
python3 -m venv venv
source venv/bin/activate    
pip install scapy
python3 pcapgen.py

# Lancer un shell interactif avec chargement du .bashrc
exec bash --login