"""
Metadata extraction module
Extracts metadata from packets without decrypting content
"""
from scapy.all import IP, TCP, UDP, rdpcap
from typing import List, Dict, Optional
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import *
from utils.helpers import save_json, format_timestamp


class MetadataExtractor:
    """Extracts metadata from network packets"""
    
    def __init__(self):
        self.metadata = []
    
    def extract_from_packets(self, packets: List) -> List[Dict]:
        """
        Extract metadata from list of Scapy packets
        
        Args:
            packets: List of Scapy packet objects
        
        Returns:
            List of metadata dictionaries
        """
        self.metadata = []
        
        for idx, pkt in enumerate(packets):
            if IP in pkt:
                metadata = self._extract_packet_metadata(pkt, idx)
                if metadata:
                    self.metadata.append(metadata)
        
        print(f"[+] Extracted metadata from {len(self.metadata)} packets")
        return self.metadata
    
    def _extract_packet_metadata(self, pkt, packet_id: int) -> Optional[Dict]:
        """
        Extract metadata from single packet
        
        Returns metadata dict with:
        - timestamp, src_ip, dst_ip, src_port, dst_port
        - protocol, packet_size, flags
        """
        try:
            # Base IP layer metadata
            metadata = {
                'packet_id': packet_id,
                'timestamp': float(pkt.time),
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'packet_size': len(pkt),
                'protocol': None,
                'src_port': None,
                'dst_port': None,
                'tcp_flags': None,
                'direction': None  # Will be set later by profiler
            }
            
            # TCP metadata
            if TCP in pkt:
                metadata['protocol'] = 'TCP'
                metadata['src_port'] = pkt[TCP].sport
                metadata['dst_port'] = pkt[TCP].dport
                metadata['tcp_flags'] = self._get_tcp_flags(pkt[TCP])
                
                # Digital Signature / JA3 Approximation (Heuristic)
                if metadata['dst_port'] in [443, 8443] or metadata['src_port'] in [443, 8443]:
                    metadata['ja3_fingerprint'] = self._compute_ja3_simple(pkt)
            
            # UDP metadata
            elif UDP in pkt:
                metadata['protocol'] = 'UDP'
                metadata['src_port'] = pkt[UDP].sport
                metadata['dst_port'] = pkt[UDP].dport
                
                # DNS Extraction
                if metadata['dst_port'] == 53 or metadata['src_port'] == 53:
                    dns_info = self.extract_dns_metadata(pkt)
                    if dns_info:
                        metadata['dns_query'] = dns_info.get('query')
                        metadata['dns_type'] = dns_info.get('type')
            
            else:
                # Other protocols
                metadata['protocol'] = str(pkt[IP].proto)
            
            return metadata
            
        except Exception as e:
            print(f"[!] Error extracting metadata from packet {packet_id}: {e}")
            return None
    
    def _get_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string (e.g., 'SA' for SYN-ACK)"""
        flags = []
        if tcp_layer.flags.S: flags.append('S')  # SYN
        if tcp_layer.flags.A: flags.append('A')  # ACK
        if tcp_layer.flags.F: flags.append('F')  # FIN
        if tcp_layer.flags.R: flags.append('R')  # RST
        if tcp_layer.flags.P: flags.append('P')  # PSH
        if tcp_layer.flags.U: flags.append('U')  # URG
        
        return ''.join(flags) if flags else ''

    def _compute_ja3_simple(self, pkt) -> str:
        """Approximation of JA3 fingerprinting (Demo implementation)"""
        import hashlib
        # In a real tool, we'd parse Client Hello (SSL/TLS extensions, ciphers, etc.)
        # Here we use a stable fingerprint of port + length sequence
        fp_basis = f"{pkt.getlayer(IP).proto}_{len(pkt)}"
        return hashlib.md5(fp_basis.encode()).hexdigest()

    def extract_dns_metadata(self, pkt) -> Optional[Dict]:
        """Extract DNS query metadata"""
        from scapy.all import DNSQR
        if pkt.haslayer(DNSQR):
            query = pkt.getlayer(DNSQR).qname.decode('utf-8')
            qtype = pkt.getlayer(DNSQR).qtype
            return {'query': query, 'type': qtype}
        return None
    
    def extract_from_pcap(self, pcap_file: str = PCAP_FILE) -> List[Dict]:
        """
        Extract metadata directly from PCAP file
        
        Args:
            pcap_file: Path to PCAP file
        
        Returns:
            List of metadata dictionaries
        """
        try:
            packets = rdpcap(pcap_file)
            print(f"[+] Loaded {len(packets)} packets from {pcap_file}")
            return self.extract_from_packets(packets)
        except Exception as e:
            print(f"[!] Error reading PCAP file: {e}")
            return []
    
    def save_metadata(self, filepath: str = METADATA_FILE) -> bool:
        """Save extracted metadata to JSON file"""
        if not self.metadata:
            print("[!] No metadata to save")
            return False
        
        try:
            save_json(self.metadata, filepath)
            print(f"[+] Saved {len(self.metadata)} metadata records to {filepath}")
            return True
        except Exception as e:
            print(f"[!] Error saving metadata: {e}")
            return False
    
    def get_summary(self) -> Dict:
        """Get summary statistics of extracted metadata"""
        if not self.metadata:
            return {}
        
        protocols = {}
        ips = set()
        ports = set()
        
        for meta in self.metadata:
            # Count protocols
            proto = meta.get('protocol', 'Unknown')
            protocols[proto] = protocols.get(proto, 0) + 1
            
            # Collect unique IPs
            ips.add(meta['src_ip'])
            ips.add(meta['dst_ip'])
            
            # Collect unique ports
            if meta['src_port']:
                ports.add(meta['src_port'])
            if meta['dst_port']:
                ports.add(meta['dst_port'])
        
        return {
            'total_records': len(self.metadata),
            'protocols': protocols,
            'unique_ips': len(ips),
            'unique_ports': len(ports),
            'time_range': {
                'start': format_timestamp(min(m['timestamp'] for m in self.metadata)),
                'end': format_timestamp(max(m['timestamp'] for m in self.metadata))
            }
        }


def main():
    """Demo: Extract metadata from PCAP file"""
    print("=" * 60)
    print("ECHO Metadata Extractor Module")
    print("=" * 60)
    
    extractor = MetadataExtractor()
    
    # Extract from PCAP
    metadata = extractor.extract_from_pcap()
    
    if metadata:
        extractor.save_metadata()
        summary = extractor.get_summary()
        
        print("\n[*] Metadata Summary:")
        print(f"    Total records: {summary.get('total_records', 0)}")
        print(f"    Protocols: {summary.get('protocols', {})}")
        print(f"    Unique IPs: {summary.get('unique_ips', 0)}")
        print(f"    Unique ports: {summary.get('unique_ports', 0)}")
        print(f"    Time range: {summary.get('time_range', {})}")
    else:
        print("\n[!] No metadata extracted")
        print("[*] Make sure PCAP file exists at:", PCAP_FILE)


if __name__ == "__main__":
    main()