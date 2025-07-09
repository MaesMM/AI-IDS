#!/usr/bin/env python3
# attack_simulation.py
import os
import subprocess
from tcp_syn_scan import create_syn_scan
from tcp_connect_scan import create_connect_scan
from udp_scan import create_udp_scan

def run_snort_test(pcap_file):
    """Run Snort with the specified PCAP file and check for alerts"""
    print(f"\n=== Testing {pcap_file} with Snort ===\n")
    
    # Remove old alert file if it exists
    if os.path.exists("/var/log/snort/alert_fast.txt"):
        os.remove("/var/log/snort/alert_fast.txt")
    
    # Create directory for alerts if needed
    os.makedirs("/var/log/snort", exist_ok=True)
    
    # Run Snort with the PCAP file
    cmd = [
        "/usr/local/snort/bin/snort",
        "--daq-dir", "/usr/local/lib/daq_s3/lib/daq",
        "-c", "/usr/local/snort/etc/snort/snort.lua",
        "-r", pcap_file,
        "-A", "fast"
    ]
    
    subprocess.run(cmd)
    
    # Check for alerts
    if os.path.exists("/var/log/snort/alert_fast.txt"):
        with open("/var/log/snort/alert_fast.txt", "r") as f:
            alerts = f.readlines()
            print(f"\nFound {len(alerts)} alerts")
            
            # Print ML-specific alerts
            ml_alerts = [a for a in alerts if "ML ALERT" in a]
            print(f"Found {len(ml_alerts)} ML model alerts")
            
            for alert in ml_alerts:
                print(alert.strip())
    else:
        print("No alerts generated")

def main():
    """Generate attack traffic and test Snort ML detection"""
    print("=== Starting Attack Simulation Tests ===")
    
    # Generate attack PCAPs
    pcaps = [
        create_syn_scan(),
        create_connect_scan(),
        create_udp_scan()
    ]
    
    # Test each PCAP with Snort
    for pcap in pcaps:
        run_snort_test(pcap)
    
    print("\n=== Attack Simulation Tests Complete ===")

if __name__ == "__main__":
    main()
