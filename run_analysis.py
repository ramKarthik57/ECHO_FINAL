"""
Complete analysis pipeline runner
"""
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.metadata_extractor import MetadataExtractor
from backend.flow_builder import FlowBuilder
from backend.burst_analyzer import BurstAnalyzer
from backend.endpoint_profiler import EndpointProfiler
from backend.graph_builder import GraphBuilder
from utils.config import *

def run_complete_analysis(suspect_ip=None):
    """
    Run complete forensic analysis pipeline
    
    Args:
        suspect_ip: IP of suspect device (auto-detected if None)
    """
    
    print("=" * 70)
    print("ECHO - Complete Forensic Analysis Pipeline")
    print("=" * 70)
    
    # Step 1: Extract metadata
    print("\n[1/6] Extracting metadata from PCAP...")
    extractor = MetadataExtractor()
    metadata = extractor.extract_from_pcap(PCAP_FILE)
    
    if not metadata:
        print("[!] ERROR: No metadata extracted!")
        print(f"[!] Make sure PCAP file exists at: {PCAP_FILE}")
        print("[*] Run: python backend/live_capture.py")
        return False
    
    extractor.save_metadata()
    
    # Step 2: Build flows
    print("\n[2/6] Building communication flows...")
    builder = FlowBuilder()
    flows = builder.build_flows(metadata)
    
    if not flows:
        print("[!] ERROR: No flows built!")
        return False
    
    builder.save_flows()
    
    # Step 3: Detect bursts
    print("\n[3/6] Detecting bursts...")
    analyzer = BurstAnalyzer()
    bursts = analyzer.detect_bursts_in_flows(flows)
    
    # Step 4: Determine suspect IP
    if not suspect_ip:
        # Auto-detect: use most active IP
        ip_counts = {}
        for flow in flows.values():
            src = flow['src_ip']
            dst = flow['dst_ip']
            ip_counts[src] = ip_counts.get(src, 0) + 1
            ip_counts[dst] = ip_counts.get(dst, 0) + 1
        
        suspect_ip = max(ip_counts.items(), key=lambda x: x[1])[0]
        print(f"[*] Auto-detected suspect IP: {suspect_ip}")
    
    # Step 5: Profile endpoints
    print("\n[4/6] Profiling endpoints...")
    profiler = EndpointProfiler()
    profiles = profiler.profile_endpoints(flows, suspect_ip)
    profiler.save_profiles()
    
    # Step 6: Find correlations
    print("\n[5/6] Finding burst correlations...")
    correlations = analyzer.find_correlated_bursts(suspect_ip)
    
    # Save correlations
    if correlations:
        from utils.helpers import save_json
        save_json(correlations, os.path.join(DATA_DIR, "correlations.json"))
    
    # Step 7: Build graph
    print("\n[6/6] Building relationship graph...")
    graph_builder = GraphBuilder()
    graph = graph_builder.build_graph(flows, profiles, suspect_ip, correlations)
    graph_builder.save_graph()
    
    # Summary
    print("\n" + "=" * 70)
    print("Analysis Complete!")
    print("=" * 70)
    print(f"\nSuspect IP: {suspect_ip}")
    print(f"Total Flows: {len(flows)}")
    print(f"Total Bursts: {len(bursts)}")
    print(f"Remote Endpoints: {len(profiles)}")
    print(f"Correlations Found: {len(correlations)}")
    
    # Top suspicious endpoints
    ranked = profiler.rank_endpoints_by_suspicion()
    if ranked:
        print(f"\nTop 3 Suspicious Endpoints:")
        for i, ep in enumerate(ranked[:3], 1):
            print(f"  {i}. {ep['remote_ip']} (Score: {ep['suspicion_score']:.1f})")
    
    print("\n" + "=" * 70)
    print("View results in dashboard:")
    print("  python dashboard/app.py")
    print("  Then open: http://localhost:8001")
    print("=" * 70)
    
    return True

if __name__ == "__main__":
    # You can specify suspect IP as argument
    suspect = sys.argv[1] if len(sys.argv) > 1 else None
    run_complete_analysis(suspect_ip=suspect)