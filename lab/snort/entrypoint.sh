#! /bin/bash
cd /usr/local/src/libml/examples/classifier
python3 -m venv venv
source venv/bin/activate    
pip install scapy
python3 pcapgen.py

# Better transfert the trained model
# pip install numpy tensorflow ...

/bin/bash