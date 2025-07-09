from scapy.all import *
import random

def create_udp_scan(output_file="udp_scan.pcap"):
    """Generate UDP port scan PCAP"""
    print(f"Generating UDP scan to {output_file}...")
    
    target_ip = "172.16.10.120"
    scanner_ip = "172.16.10.102"
    
    packets = []
    # UDP port scan - simpler than TCP scans
    for port in range(100, 200):
        # Random source port
        src_port = random.randint(49152, 65535)
        
        # UDP probe packet (empty payload)
        udp_probe = IP(src=scanner_ip, dst=target_ip) / UDP(sport=src_port, dport=port)
        
        # For closed ports, target responds with ICMP Port Unreachable
        if port % 10 != 0:  # 90% of ports are "closed"
            icmp_response = IP(src=target_ip, dst=scanner_ip) / \
                         ICMP(type=3, code=3) / \
                         UDP(sport=port, dport=src_port)
            packets.extend([udp_probe, icmp_response])
        else:
            # For "open" ports, no response (which is typical for open UDP ports)
            packets.append(udp_probe)
    
    wrpcap(output_file, packets)
    print(f"Created {output_file} with {len(packets)} packets")
    return output_file

if __name__ == "__main__":
    create_udp_scan()
