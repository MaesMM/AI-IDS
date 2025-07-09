from scapy.all import *
import random
import time

def create_connect_scan(output_file="tcp_connect_scan.pcap"):
    """Generate a full TCP connect scan PCAP"""
    print(f"Generating TCP Connect scan to {output_file}...")
    
    # Setup IP addresses
    target_ip = "172.16.10.120"
    scanner_ip = "172.16.10.102"
    
    packets = []
    # Scan fewer ports but with full connections
    for port in range(20, 40):
        # Random source port
        src_port = random.randint(49152, 65535)
        
        # 1. TCP SYN
        syn = IP(src=scanner_ip, dst=target_ip) / TCP(sport=src_port, dport=port, flags='S')
        
        # Every 5th port is "open" - simulate full connection
        if port % 5 == 0:
            # 2. SYN-ACK from server
            syn_ack = IP(src=target_ip, dst=scanner_ip) / TCP(sport=port, dport=src_port, 
                                                           flags='SA', seq=random.randint(1000, 9000))
            # 3. ACK from client
            ack = IP(src=scanner_ip, dst=target_ip) / TCP(sport=src_port, dport=port, 
                                                       flags='A', seq=syn.seq + 1)
            # 4. FIN from client to close connection
            fin = IP(src=scanner_ip, dst=target_ip) / TCP(sport=src_port, dport=port, 
                                                       flags='FA', seq=syn.seq + 2)
            # 5. FIN-ACK from server
            fin_ack = IP(src=target_ip, dst=scanner_ip) / TCP(sport=port, dport=src_port, 
                                                           flags='FA')
            # 6. Final ACK from client
            final_ack = IP(src=scanner_ip, dst=target_ip) / TCP(sport=src_port, dport=port, 
                                                             flags='A')
            
            packets.extend([syn, syn_ack, ack, fin, fin_ack, final_ack])
        else:
            # Closed port - just RST+ACK response
            rst = IP(src=target_ip, dst=scanner_ip) / TCP(sport=port, dport=src_port, 
                                                       flags='RA', seq=0)
            packets.extend([syn, rst])
    
    wrpcap(output_file, packets)
    print(f"Created {output_file} with {len(packets)} packets")
    return output_file

if __name__ == "__main__":
    create_connect_scan()
