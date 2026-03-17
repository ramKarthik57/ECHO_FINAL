"""
Live packet capture with interface selection
"""
from scapy.all import sniff, wrpcap, conf
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import *
from utils.network_helper import select_interface

def capture_live_traffic(interface=None, count=200, timeout=60):
    """
    Capture live network traffic
    
    Args:
        interface: Network interface (None = auto-select)
        count: Number of packets to capture
        timeout: Timeout in seconds
    """
    
    if not interface:
        print("[*] No interface specified, starting interface selection...")
        interface = select_interface()
        
        if not interface:
            print("[!] No interface selected. Exiting.")
            return None
    
    print("\n" + "=" * 70)
    print("ECHO Live Packet Capture")
    print("=" * 70)
    print(f"Interface: {interface}")
    print(f"Packets: {count}")
    print(f"Timeout: {timeout} seconds")
    print(f"Filter: tcp or udp")
    print("=" * 70)
    
    # Windows-specific: You might need to run as administrator
    print("\n[!] IMPORTANT: On Windows, you may need to:")
    print("    1. Run Command Prompt as Administrator")
    print("    2. Install Npcap (if not already installed)")
    print("    3. Make sure your antivirus allows packet capture")
    
    input("\n[*] Press Enter to start capture (or Ctrl+C to cancel)...")
    
    try:
        print(f"\n[*] Starting capture on {interface}...")
        print("[*] Generating some network traffic (browse web, use apps)...")
        print("[*] Capturing packets...\n")
        
        packets = sniff(
            iface=interface,
            filter="tcp or udp",
            count=count,
            timeout=timeout
        )
        
        if packets:
            print(f"\n[+] Captured {len(packets)} packets!")
            
            # Save to PCAP
            wrpcap(PCAP_FILE, packets)
            print(f"[+] Saved to: {PCAP_FILE}")
            
            # Show summary
            print(f"\n[*] Packet Summary:")
            protocols = {}
            for pkt in packets:
                proto = pkt.sprintf("%IP.proto%")
                protocols[proto] = protocols.get(proto, 0) + 1
            
            for proto, count in protocols.items():
                print(f"    {proto}: {count} packets")
            
            return packets
        else:
            print("\n[!] No packets captured!")
            print("[*] Troubleshooting:")
            print("    - Make sure you have network activity")
            print("    - Try running as Administrator")
            print("    - Check if Npcap is installed")
            return None
            
    except PermissionError:
        print("\n[!] ERROR: Permission denied!")
        print("[*] On Windows, you need to:")
        print("    1. Right-click Command Prompt")
        print("    2. Select 'Run as Administrator'")
        print("    3. Run this script again")
        return None
        
    except Exception as e:
        print(f"\n[!] Capture error: {e}")
        print("\n[*] Troubleshooting:")
        print("    - Install Npcap from: https://npcap.com/")
        print("    - Run as Administrator")
        print("    - Check antivirus/firewall settings")
        return None

def main():
    """Main entry point"""
    
    # Option 1: Auto-select interface
    packets = capture_live_traffic(count=200, timeout=60)
    
    if packets:
        print("\n" + "=" * 70)
        print("[✓] Capture successful!")
        print("=" * 70)
        print("\n[*] Next steps:")
        print("    1. python backend/metadata_extractor.py")
        print("    2. python backend/flow_builder.py")
        print("    3. python backend/burst_analyzer.py")
        print("    4. python backend/endpoint_profiler.py")
        print("    5. python backend/graph_builder.py")
        print("    6. python dashboard/app.py")
        print("\n[*] Or run the full pipeline with run_analysis.py")

if __name__ == "__main__":
    main()