"""
Packet capture module using Scapy
Captures network packets and saves to PCAP file
"""
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP
from typing import List, Dict, Optional
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import *


class PacketCapture:
    """Handles packet capture operations"""
    
    def __init__(self, interface: str = CAPTURE_INTERFACE, pcap_file: str = PCAP_FILE):
        self.interface = interface
        self.pcap_file = pcap_file
        self.packets = []
    
    def capture_live(self, count: int = PACKET_COUNT, timeout: int = CAPTURE_TIMEOUT, 
                     filter_str: str = CAPTURE_FILTER) -> List:
        """
        Capture packets from network interface in real-time
        
        Args:
            count: Number of packets to capture (0 = unlimited)
            timeout: Capture timeout in seconds
            filter_str: BPF filter string
        
        Returns:
            List of captured packets
        """
        print(f"[*] Starting packet capture on {self.interface}")
        print(f"[*] Filter: {filter_str}")
        print(f"[*] Count: {count if count > 0 else 'unlimited'}, Timeout: {timeout}s")
        
        try:
            self.packets = sniff(
                iface=self.interface,
                filter=filter_str,
                count=count,
                timeout=timeout
            )
            
            print(f"[+] Captured {len(self.packets)} packets")
            return self.packets
            
        except PermissionError:
            print("[!] Error: Packet capture requires root/admin privileges")
            print("[!] Run with: sudo python3 backend/packet_capture.py")
            return []
        except Exception as e:
            print(f"[!] Capture error: {e}")
            return []
    
    def save_to_pcap(self, packets: Optional[List] = None) -> bool:
        """
        Save captured packets to PCAP file
        
        Args:
            packets: List of packets to save (uses self.packets if None)
        
        Returns:
            True if successful, False otherwise
        """
        packets_to_save = packets if packets is not None else self.packets
        
        if not packets_to_save:
            print("[!] No packets to save")
            return False
        
        try:
            wrpcap(self.pcap_file, packets_to_save)
            print(f"[+] Saved {len(packets_to_save)} packets to {self.pcap_file}")
            return True
        except Exception as e:
            print(f"[!] Error saving PCAP: {e}")
            return False
    
    def load_from_pcap(self, pcap_file: Optional[str] = None) -> List:
        """
        Load packets from existing PCAP file
        
        Args:
            pcap_file: Path to PCAP file (uses self.pcap_file if None)
        
        Returns:
            List of packets
        """
        file_path = pcap_file if pcap_file is not None else self.pcap_file
        
        try:
            self.packets = rdpcap(file_path)
            print(f"[+] Loaded {len(self.packets)} packets from {file_path}")
            return self.packets
        except FileNotFoundError:
            print(f"[!] PCAP file not found: {file_path}")
            return []
        except Exception as e:
            print(f"[!] Error loading PCAP: {e}")
            return []
    
    def get_packet_summary(self) -> Dict:
        """Get summary statistics of captured packets"""
        if not self.packets:
            return {}
        
        protocols = {}
        for pkt in self.packets:
            if IP in pkt:
                proto = pkt[IP].proto
                proto_name = {6: 'TCP', 17: 'UDP'}.get(proto, f'Other({proto})')
                protocols[proto_name] = protocols.get(proto_name, 0) + 1
        
        return {
            'total_packets': len(self.packets),
            'protocols': protocols,
            'pcap_file': self.pcap_file
        }


def main():
    """Demo: Capture packets and save to PCAP"""
    print("=" * 60)
    print("ECHO Packet Capture Module")
    print("=" * 60)
    
    capturer = PacketCapture()
    
    # Try to capture live packets
    packets = capturer.capture_live(count=100, timeout=30)
    
    if packets:
        capturer.save_to_pcap()
        summary = capturer.get_packet_summary()
        print("\n[*] Capture Summary:")
        print(f"    Total packets: {summary.get('total_packets', 0)}")
        print(f"    Protocols: {summary.get('protocols', {})}")
    else:
        print("\n[!] No packets captured - using demo mode")
        print("[*] In production, run with sudo for live capture")


if __name__ == "__main__":
    main()