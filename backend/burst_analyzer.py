"""
Burst analyzer module
Detects message bursts and identifies temporal correlations
"""
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import *
from utils.helpers import (
    group_by_time_window, 
    calculate_burst_stats, 
    save_json, 
    load_json,
    calculate_time_delta
)


class BurstAnalyzer:
    """Analyzes traffic bursts and temporal correlations"""
    
    def __init__(self, burst_threshold: float = BURST_THRESHOLD, 
                 min_burst_packets: int = MIN_BURST_PACKETS,
                 correlation_window: float = CORRELATION_WINDOW):
        self.burst_threshold = burst_threshold
        self.min_burst_packets = min_burst_packets
        self.correlation_window = correlation_window
        self.bursts = []
        self.correlations = []
    
    def detect_bursts_in_flows(self, flows: Dict[str, Dict]) -> List[Dict]:
        """
        Detect bursts within each flow
        
        Args:
            flows: Dictionary of flow objects
        
        Returns:
            List of detected bursts
        """
        self.bursts = []
        
        for flow_id, flow in flows.items():
            packets = flow.get('packets', [])
            
            if len(packets) < self.min_burst_packets:
                continue
            
            # Detect bursts in this flow
            flow_bursts = self._detect_bursts_in_packets(packets, flow_id)
            self.bursts.extend(flow_bursts)
        
        print(f"[+] Detected {len(self.bursts)} bursts across {len(flows)} flows")
        return self.bursts
    
    def _detect_bursts_in_packets(self, packets: List[Dict], flow_id: str) -> List[Dict]:
        """
        Detect bursts within a packet list based on timing gaps
        
        A burst is a group of packets with inter-arrival times < threshold
        """
        if not packets:
            return []
        
        sorted_packets = sorted(packets, key=lambda x: x['timestamp'])
        bursts = []
        current_burst = [sorted_packets[0]]
        
        for i in range(1, len(sorted_packets)):
            time_gap = sorted_packets[i]['timestamp'] - current_burst[-1]['timestamp']
            
            if time_gap <= self.burst_threshold:
                # Packet belongs to current burst
                current_burst.append(sorted_packets[i])
            else:
                # Gap too large - save current burst and start new one
                if len(current_burst) >= self.min_burst_packets:
                    bursts.append(self._create_burst_object(current_burst, flow_id))
                current_burst = [sorted_packets[i]]
        
        # Don't forget last burst
        if len(current_burst) >= self.min_burst_packets:
            bursts.append(self._create_burst_object(current_burst, flow_id))
        
        return bursts
    
    def _create_burst_object(self, packets: List[Dict], flow_id: str) -> Dict:
        """Create a burst object with statistics"""
        stats = calculate_burst_stats(packets)
        
        # Determine burst direction (majority of packets)
        src_ips = [p['src_ip'] for p in packets]
        most_common_src = max(set(src_ips), key=src_ips.count)
        
        burst = {
            'flow_id': flow_id,
            'src_ip': most_common_src,
            'dst_ip': packets[0]['dst_ip'],
            'start_time': stats['start_time'],
            'end_time': stats['end_time'],
            'duration': stats['duration'],
            'packet_count': stats['packet_count'],
            'total_bytes': stats['total_bytes'],
            'avg_packet_size': stats['avg_packet_size'],
            'direction': 'outbound' if packets[0]['src_ip'] == most_common_src else 'inbound'
        }
        
        return burst
    
    def find_correlated_bursts(self, suspect_ip: str) -> List[Dict]:
        """
        Find bursts that are temporally correlated
        Looks for response bursts from remote IPs after suspect sends
        
        Args:
            suspect_ip: IP address of the suspect device
        
        Returns:
            List of correlation objects
        """
        if not self.bursts:
            print("[!] No bursts to correlate")
            return []
        
        # Separate suspect bursts from remote bursts
        suspect_bursts = [b for b in self.bursts if b['src_ip'] == suspect_ip]
        remote_bursts = [b for b in self.bursts if b['src_ip'] != suspect_ip]
        
        print(f"[*] Analyzing {len(suspect_bursts)} suspect bursts vs {len(remote_bursts)} remote bursts")
        
        self.correlations = []
        
        # For each suspect burst, find temporally close remote bursts
        for suspect_burst in suspect_bursts:
            suspect_end = suspect_burst['end_time']
            
            for remote_burst in remote_bursts:
                remote_start = remote_burst['start_time']
                
                # Calculate time delta
                time_delta = remote_start - suspect_end
                
                # Check if within correlation window and after suspect burst
                if 0 < time_delta <= self.correlation_window:
                    correlation_score = self._calculate_correlation_score(
                        suspect_burst, remote_burst, time_delta
                    )
                    
                    if correlation_score >= MIN_CORRELATION_SCORE:
                        self.correlations.append({
                            'suspect_burst': suspect_burst,
                            'remote_burst': remote_burst,
                            'time_delta': time_delta,
                            'correlation_score': correlation_score,
                            'remote_ip': remote_burst['src_ip'],
                            'suspect_ip': suspect_ip
                        })
        
        print(f"[+] Found {len(self.correlations)} correlated burst pairs")
        return self.correlations
    
    def _calculate_correlation_score(self, suspect_burst: Dict, 
                                     remote_burst: Dict, time_delta: float) -> float:
        """
        Calculate correlation score between two bursts
        Score based on: temporal proximity, size similarity
        """
        # Temporal score (closer = better)
        temporal_score = 1.0 - (time_delta / self.correlation_window)
        
        # Size similarity score
        suspect_size = suspect_burst['total_bytes']
        remote_size = remote_burst['total_bytes']
        max_size = max(suspect_size, remote_size)
        min_size = min(suspect_size, remote_size)
        size_score = min_size / max_size if max_size > 0 else 0
        
        # Combined score (weighted average)
        correlation_score = (0.7 * temporal_score) + (0.3 * size_score)
        
        return correlation_score
    
    def get_top_correlated_endpoints(self, top_n: int = 10) -> List[Dict]:
        """
        Get top N remote endpoints by correlation frequency
        
        Returns ranked list of endpoints with correlation counts
        """
        if not self.correlations:
            return []
        
        # Count correlations per remote IP
        endpoint_counts = defaultdict(lambda: {
            'count': 0, 
            'avg_score': 0, 
            'total_score': 0,
            'avg_time_delta': 0,
            'total_time_delta': 0
        })
        
        for corr in self.correlations:
            remote_ip = corr['remote_ip']
            endpoint_counts[remote_ip]['count'] += 1
            endpoint_counts[remote_ip]['total_score'] += corr['correlation_score']
            endpoint_counts[remote_ip]['total_time_delta'] += corr['time_delta']
        
        # Calculate averages and rank
        ranked = []
        for ip, data in endpoint_counts.items():
            ranked.append({
                'remote_ip': ip,
                'correlation_count': data['count'],
                'avg_correlation_score': data['total_score'] / data['count'],
                'avg_response_time': data['total_time_delta'] / data['count']
            })
        
        # Sort by correlation count (descending)
        ranked.sort(key=lambda x: x['correlation_count'], reverse=True)
        
        return ranked[:top_n]
    
    def save_results(self, bursts_file: str = None, correlations_file: str = None) -> bool:
        """Save burst and correlation analysis results"""
        try:
            if bursts_file and self.bursts:
                save_json(self.bursts, bursts_file)
                print(f"[+] Saved {len(self.bursts)} bursts to {bursts_file}")
            
            if correlations_file and self.correlations:
                save_json(self.correlations, correlations_file)
                print(f"[+] Saved {len(self.correlations)} correlations to {correlations_file}")
            
            return True
        except Exception as e:
            print(f"[!] Error saving results: {e}")
            return False


def main():
    """Demo: Detect bursts and correlations"""
    print("=" * 60)
    print("ECHO Burst Analyzer Module")
    print("=" * 60)
    
    # Load flows
    flows_data = load_json(FLOWS_FILE)
    
    if not flows_data:
        print("[!] No flows found")
        print(f"[*] Run flow_builder.py first to generate {FLOWS_FILE}")
        return
    
    # Convert to dict if needed
    if isinstance(flows_data, list):
        flows = {f['flow_id']: f for f in flows_data}
    else:
        flows = flows_data
    
    # Analyze bursts
    analyzer = BurstAnalyzer()
    bursts = analyzer.detect_bursts_in_flows(flows)
    
    if bursts:
        print(f"\n[*] Sample burst:")
        print(f"    {bursts[0]}")
        
        # Find correlations (using first IP as suspect for demo)
        if flows:
            first_flow = list(flows.values())[0]
            suspect_ip = first_flow['src_ip']
            print(f"\n[*] Using {suspect_ip} as suspect IP for correlation analysis")
            
            correlations = analyzer.find_correlated_bursts(suspect_ip)
            
            if correlations:
                top_endpoints = analyzer.get_top_correlated_endpoints(5)
                print(f"\n[*] Top correlated endpoints:")
                for ep in top_endpoints:
                    print(f"    {ep['remote_ip']}: {ep['correlation_count']} correlations, "
                          f"score={ep['avg_correlation_score']:.2f}")


if __name__ == "__main__":
    main()