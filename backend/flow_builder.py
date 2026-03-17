"""
Flow builder module
Groups packets into bidirectional communication flows/sessions
"""
from typing import List, Dict, Optional
from collections import defaultdict
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import *
from utils.helpers import generate_flow_key, save_json, load_json, format_timestamp


class FlowBuilder:
    """Builds communication flows from packet metadata"""
    
    def __init__(self, flow_timeout: int = FLOW_TIMEOUT):
        self.flow_timeout = flow_timeout
        self.flows = {}
        self.flow_stats = []
    
    def build_flows(self, metadata: List[Dict]) -> Dict[str, Dict]:
        """
        Group packets into bidirectional flows
        
        Args:
            metadata: List of packet metadata dictionaries
        
        Returns:
            Dictionary of flows keyed by flow_id
        """
        if not metadata:
            print("[!] No metadata provided")
            return {}
        
        # Sort by timestamp
        sorted_metadata = sorted(metadata, key=lambda x: x['timestamp'])
        
        # Group packets into flows
        flow_packets = defaultdict(list)
        
        for meta in sorted_metadata:
            # Generate flow key
            flow_key = generate_flow_key(
                meta['src_ip'],
                meta['dst_ip'],
                meta.get('src_port', 0),
                meta.get('dst_port', 0),
                meta.get('protocol', 'unknown')
            )
            
            flow_packets[flow_key].append(meta)
        
        # Build flow objects with statistics
        self.flows = {}
        for flow_id, packets in flow_packets.items():
            self.flows[flow_id] = self._create_flow_object(flow_id, packets)
        
        print(f"[+] Built {len(self.flows)} flows from {len(metadata)} packets")
        return self.flows
    
    def _create_flow_object(self, flow_id: str, packets: List[Dict]) -> Dict:
        """
        Create a flow object with statistics
        
        Returns flow dict with:
        - flow_id, endpoints, timestamps, packet_count, total_bytes
        - upload/download stats, duration
        """
        if not packets:
            return {}
        
        # Sort packets by timestamp
        packets = sorted(packets, key=lambda x: x['timestamp'])
        
        # Extract endpoints (first packet defines flow direction)
        first_pkt = packets[0]
        
        flow = {
            'flow_id': flow_id,
            'src_ip': first_pkt['src_ip'],
            'dst_ip': first_pkt['dst_ip'],
            'src_port': first_pkt.get('src_port'),
            'dst_port': first_pkt.get('dst_port'),
            'protocol': first_pkt.get('protocol'),
            'start_time': packets[0]['timestamp'],
            'end_time': packets[-1]['timestamp'],
            'duration': packets[-1]['timestamp'] - packets[0]['timestamp'],
            'packet_count': len(packets),
            'packets': packets
        }
        
        # Calculate traffic statistics
        flow.update(self._calculate_traffic_stats(packets, first_pkt))
        
        return flow
    
    def _calculate_traffic_stats(self, packets: List[Dict], first_pkt: Dict) -> Dict:
        """Calculate upload/download statistics for flow"""
        
        src_ip = first_pkt['src_ip']
        dst_ip = first_pkt['dst_ip']
        
        upload_bytes = 0
        download_bytes = 0
        upload_packets = 0
        download_packets = 0
        
        for pkt in packets:
            size = pkt['packet_size']
            
            if pkt['src_ip'] == src_ip and pkt['dst_ip'] == dst_ip:
                # Outbound from original source
                upload_bytes += size
                upload_packets += 1
            else:
                # Inbound to original source
                download_bytes += size
                download_packets += 1
        
        total_bytes = upload_bytes + download_bytes
        
        return {
            'total_bytes': total_bytes,
            'upload_bytes': upload_bytes,
            'download_bytes': download_bytes,
            'upload_packets': upload_packets,
            'download_packets': download_packets,
            'upload_download_ratio': upload_bytes / download_bytes if download_bytes > 0 else float('inf'),
            'avg_packet_size': total_bytes / len(packets) if packets else 0
        }
    
    def get_flow_summary(self) -> List[Dict]:
        """
        Get summary statistics for all flows
        Removes packet-level data for cleaner storage
        """
        self.flow_stats = []
        
        for flow_id, flow in self.flows.items():
            # Create summary without packet list
            summary = {k: v for k, v in flow.items() if k != 'packets'}
            summary['flow_id'] = flow_id
            self.flow_stats.append(summary)
        
        return self.flow_stats
    
    def save_flows(self, filepath: str = FLOWS_FILE, include_packets: bool = False) -> bool:
        """
        Save flows to JSON file
        
        Args:
            filepath: Output file path
            include_packets: If True, include all packet data (large file)
        """
        if not self.flows:
            print("[!] No flows to save")
            return False
        
        try:
            if include_packets:
                # Save complete flows with packets
                save_json(self.flows, filepath)
            else:
                # Save only flow summaries (lighter)
                summaries = self.get_flow_summary()
                save_json(summaries, filepath)
            
            print(f"[+] Saved {len(self.flows)} flows to {filepath}")
            return True
        except Exception as e:
            print(f"[!] Error saving flows: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get overall flow statistics"""
        if not self.flows:
            return {}
        
        durations = [f['duration'] for f in self.flows.values()]
        byte_counts = [f['total_bytes'] for f in self.flows.values()]
        packet_counts = [f['packet_count'] for f in self.flows.values()]
        
        # Get unique IPs
        all_ips = set()
        for flow in self.flows.values():
            all_ips.add(flow['src_ip'])
            all_ips.add(flow['dst_ip'])
        
        return {
            'total_flows': len(self.flows),
            'unique_ips': len(all_ips),
            'avg_flow_duration': sum(durations) / len(durations),
            'total_bytes': sum(byte_counts),
            'avg_bytes_per_flow': sum(byte_counts) / len(byte_counts),
            'avg_packets_per_flow': sum(packet_counts) / len(packet_counts)
        }


def main():
    """Demo: Build flows from metadata"""
    print("=" * 60)
    print("ECHO Flow Builder Module")
    print("=" * 60)
    
    # Load metadata
    metadata = load_json(METADATA_FILE)
    
    if not metadata:
        print("[!] No metadata found")
        print(f"[*] Run metadata_extractor.py first to generate {METADATA_FILE}")
        return
    
    # Build flows
    builder = FlowBuilder()
    flows = builder.build_flows(metadata)
    
    if flows:
        builder.save_flows()
        stats = builder.get_statistics()
        
        print("\n[*] Flow Statistics:")
        print(f"    Total flows: {stats.get('total_flows', 0)}")
        print(f"    Unique IPs: {stats.get('unique_ips', 0)}")
        print(f"    Avg flow duration: {stats.get('avg_flow_duration', 0):.2f}s")
        print(f"    Total bytes: {stats.get('total_bytes', 0):,}")
        print(f"    Avg packets/flow: {stats.get('avg_packets_per_flow', 0):.1f}")
    else:
        print("\n[!] No flows built")


if __name__ == "__main__":
    main()