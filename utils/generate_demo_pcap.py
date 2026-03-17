"""
Generate demo PCAP file for testing without live capture
"""
from scapy.all import IP, TCP, UDP, wrpcap, Ether
import random
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import PCAP_FILE, DATA_DIR

def generate_demo_traffic():
    """Generate realistic demo network traffic"""
    
    packets = []
    
    # Simulate suspect communicating with remote endpoints
    suspect_ip = "192.168.1.100"
    remote_ips = [
        "185.220.101.45",  # Remote server 1
        "104.244.76.88",   # Remote server 2
        "172.67.154.92",   # Remote server 3
    ]
    
    base_time = time.time()
    current_time = base_time
    
    print(f"[*] Generating demo traffic...")
    print(f"[*] Suspect IP: {suspect_ip}")
    print(f"[*] Remote endpoints: {len(remote_ips)}")
    
    # Generate 500 packets over 5 minutes
    for i in range(500):
        # Pick random remote endpoint
        remote_ip = random.choice(remote_ips)
        
        # Simulate bursts (groups of packets close together)
        if i % 20 == 0:
            # Start new burst
            current_time += random.uniform(5, 15)  # Gap between bursts
        else:
            # Within burst
            current_time += random.uniform(0.01, 0.5)
        
        # Alternate direction
        if random.random() > 0.5:
            src_ip = suspect_ip
            dst_ip = remote_ip
            src_port = random.randint(50000, 60000)
            dst_port = 443  # HTTPS
        else:
            src_ip = remote_ip
            dst_ip = suspect_ip
            src_port = 443
            dst_port = random.randint(50000, 60000)
        
        # Create packet
        pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
        pkt.time = current_time
        
        # Add some payload (simulate encrypted data)
        payload_size = random.randint(100, 1500)
        pkt = pkt / ("X" * payload_size)
        
        packets.append(pkt)
    
    return packets

def main():
    """Generate and save demo PCAP"""
    print("=" * 60)
    print("ECHO Demo PCAP Generator")
    print("=" * 60)
    
    # Ensure data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # Generate traffic
    packets = generate_demo_traffic()
    
    # Save to PCAP
    wrpcap(PCAP_FILE, packets)
    
    print(f"\n[+] Generated {len(packets)} demo packets")
    print(f"[+] Saved to: {PCAP_FILE}")
    print(f"\n[*] You can now run the analysis pipeline:")
    print(f"    python backend/metadata_extractor.py")
    print(f"    python backend/flow_builder.py")
    print(f"    python backend/burst_analyzer.py")

if __name__ == "__main__":
    main()