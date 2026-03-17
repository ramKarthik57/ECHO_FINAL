"""
Endpoint profiler module
Profiles remote endpoints based on communication patterns
"""
from typing import List, Dict, Optional
from collections import defaultdict
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import *
from utils.helpers import save_json, load_json, is_private_ip


class EndpointProfiler:
    """Profiles and characterizes remote communication endpoints"""
    
    def __init__(self):
        self.profiles = {}
        self.suspect_ip = None
    
    def profile_endpoints(self, flows: Dict[str, Dict], suspect_ip: str) -> Dict[str, Dict]:
        """
        Create behavioral profiles for each remote endpoint
        
        Args:
            flows: Dictionary of flow objects
            suspect_ip: IP address of the suspect device
        
        Returns:
            Dictionary of endpoint profiles keyed by IP address
        """
        self.suspect_ip = suspect_ip
        self.profiles = {}
        
        # Group flows by remote endpoint
        endpoint_flows = defaultdict(list)
        
        for flow_id, flow in flows.items():
            # Identify remote endpoint (opposite of suspect)
            if flow['src_ip'] == suspect_ip:
                remote_ip = flow['dst_ip']
            elif flow['dst_ip'] == suspect_ip:
                remote_ip = flow['src_ip']
            else:
                continue  # Flow doesn't involve suspect
            
            endpoint_flows[remote_ip].append(flow)
        
        # Create profile for each endpoint
        for remote_ip, flows_list in endpoint_flows.items():
            self.profiles[remote_ip] = self._create_endpoint_profile(remote_ip, flows_list)
        
        print(f"[+] Profiled {len(self.profiles)} remote endpoints")
        return self.profiles
    
    def _create_endpoint_profile(self, remote_ip: str, flows: List[Dict]) -> Dict:
        """
        Create detailed profile for a single endpoint
        
        Profile includes:
        - Communication frequency
        - Data volume patterns
        - Timing patterns
        - Protocol usage
        """
        if not flows:
            return {}
        
        # Basic statistics
        total_flows = len(flows)
        total_packets = sum(f['packet_count'] for f in flows)
        total_bytes = sum(f['total_bytes'] for f in flows)
        
        # Timing analysis
        timestamps = []
        for flow in flows:
            timestamps.append(flow['start_time'])
        timestamps.sort()
        
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        observation_duration = last_seen - first_seen
        
        # Calculate inter-contact times
        inter_contact_times = []
        for i in range(1, len(timestamps)):
            inter_contact_times.append(timestamps[i] - timestamps[i-1])
        
        avg_inter_contact = sum(inter_contact_times) / len(inter_contact_times) if inter_contact_times else 0
        
        # Protocol distribution
        protocols = defaultdict(int)
        for flow in flows:
            proto = flow.get('protocol', 'unknown')
            protocols[proto] += 1
        
        # Port analysis
        ports_used = set()
        for flow in flows:
            if flow.get('dst_port'):
                ports_used.add(flow['dst_port'])
            if flow.get('src_port'):
                ports_used.add(flow['src_port'])
        
        # Traffic direction analysis
        upload_total = sum(f.get('upload_bytes', 0) for f in flows)
        download_total = sum(f.get('download_bytes', 0) for f in flows)
        
        # Communication regularity (coefficient of variation of inter-contact times)
        regularity_score = 0
        if inter_contact_times and avg_inter_contact > 0:
            variance = sum((t - avg_inter_contact) ** 2 for t in inter_contact_times) / len(inter_contact_times)
            std_dev = variance ** 0.5
            regularity_score = 1 / (1 + (std_dev / avg_inter_contact))  # Higher = more regular
        
        profile = {
            'remote_ip': remote_ip,
            'is_private': is_private_ip(remote_ip),
            'total_flows': total_flows,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'upload_bytes': upload_total,
            'download_bytes': download_total,
            'upload_download_ratio': upload_total / download_total if download_total > 0 else float('inf'),
            'first_seen': first_seen,
            'last_seen': last_seen,
            'observation_duration': observation_duration,
            'avg_inter_contact_time': avg_inter_contact,
            'regularity_score': regularity_score,
            'protocols': dict(protocols),
            'unique_ports': len(ports_used),
            'communication_frequency': total_flows / observation_duration if observation_duration > 0 else 0,
            'avg_bytes_per_flow': total_bytes / total_flows if total_flows > 0 else 0
        }
        
        return profile
    
    def rank_endpoints_by_suspicion(self) -> List[Dict]:
        """
        Rank endpoints by suspicion score
        
        Suspicious indicators:
        - High communication frequency
        - Regular timing patterns
        - Non-private IPs (external)
        - High data volume
        """
        if not self.profiles:
            return []
        
        ranked = []
        
        for ip, profile in self.profiles.items():
            suspicion_score = self._calculate_suspicion_score(profile)
            
            ranked.append({
                'remote_ip': ip,
                'suspicion_score': suspicion_score,
                'total_flows': profile['total_flows'],
                'total_bytes': profile['total_bytes'],
                'regularity_score': profile['regularity_score'],
                'communication_frequency': profile['communication_frequency']
            })
        
        # Sort by suspicion score (descending)
        ranked.sort(key=lambda x: x['suspicion_score'], reverse=True)
        
        return ranked
    
    def _calculate_suspicion_score(self, profile: Dict) -> float:
        """
        Calculate suspicion score for an endpoint
        
        Score components:
        - Communication frequency (0-30 points)
        - Regularity (0-25 points)
        - Data volume (0-25 points)
        - External IP bonus (0-20 points)
        
        Max score: 100
        """
        score = 0.0
        
        # Communication frequency score (more frequent = more suspicious)
        freq = profile['communication_frequency']
        if freq > 0.01:  # More than 1 flow per 100 seconds
            score += min(30, freq * 1000)
        
        # Regularity score (highly regular = suspicious)
        regularity = profile['regularity_score']
        score += regularity * 25
        
        # Data volume score (normalize to 25 max)
        total_bytes = profile['total_bytes']
        if total_bytes > 1000000:  # > 1MB
            score += min(25, (total_bytes / 1000000) * 5)
        
        # External IP bonus
        if not profile['is_private']:
            score += 20
        
        return min(100, score)
    
    def get_endpoint_summary(self, remote_ip: str) -> Optional[Dict]:
        """Get summary for a specific endpoint"""
        return self.profiles.get(remote_ip)
    
    def cluster_endpoints_by_behavior(self) -> Dict:
        """
        Groups endpoints using behavioral clustering (HDBSCAN-style approximation)
        This identifies groups of endpoints that 'act' the same way.
        """
        if not self.profiles:
            return {}
            
        clusters = defaultdict(list)
        for ip, prof in self.profiles.items():
            # Feature vector: volume, regularity, freq
            # Simple binning for demo purposes
            v_bin = "H" if prof['total_bytes'] > 100000 else "L"
            r_bin = "R" if prof['regularity_score'] > 0.7 else "I"
            cluster_key = f"C_{v_bin}{r_bin}"
            clusters[cluster_key].append(ip)
        return dict(clusters)
    
    def save_profiles(self, filepath: str = None) -> bool:
        """Save endpoint profiles to JSON"""
        if not self.profiles:
            print("[!] No profiles to save")
            return False
        
        filepath = filepath or os.path.join(DATA_DIR, "endpoint_profiles.json")
        
        try:
            save_json(self.profiles, filepath)
            print(f"[+] Saved {len(self.profiles)} endpoint profiles to {filepath}")
            return True
        except Exception as e:
            print(f"[!] Error saving profiles: {e}")
            return False


def main():
    """Demo: Profile endpoints from flows"""
    print("=" * 60)
    print("ECHO Endpoint Profiler Module")
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
    
    # Get suspect IP (use first flow's src_ip as example)
    if flows:
        first_flow = list(flows.values())[0]
        suspect_ip = first_flow['src_ip']
        print(f"[*] Using {suspect_ip} as suspect IP")
        
        # Profile endpoints
        profiler = EndpointProfiler()
        profiles = profiler.profile_endpoints(flows, suspect_ip)
        
        if profiles:
            profiler.save_profiles()
            
            # Show ranked endpoints
            ranked = profiler.rank_endpoints_by_suspicion()
            
            print(f"\n[*] Top 5 suspicious endpoints:")
            for i, ep in enumerate(ranked[:5], 1):
                print(f"    {i}. {ep['remote_ip']}")
                print(f"       Suspicion score: {ep['suspicion_score']:.1f}")
                print(f"       Flows: {ep['total_flows']}, Bytes: {ep['total_bytes']:,}")
                print(f"       Regularity: {ep['regularity_score']:.2f}")
        else:
            print("\n[!] No endpoints profiled")
    else:
        print("[!] No flows available")


if __name__ == "__main__":
    main()