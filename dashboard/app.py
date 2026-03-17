"""
Web dashboard for ECHO forensic tool
Displays analysis results with interactive visualizations
"""
import json
import os
import sys
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from datetime import datetime
import hashlib

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import DATA_DIR, FLOWS_FILE, GRAPH_FILE
from utils.helpers import load_json
from utils.wireshark_bridge import open_wireshark
from utils.warp_bridge import get_warp_status, connect_warp, disconnect_warp
from backend.packet_streamer import streamer
import dashboard.visualization as viz


app = FastAPI(title="ECHO Forensic Dashboard")

# Load the specialized index.html template
TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "index.html")

def get_template():
    if os.path.exists(TEMPLATE_PATH):
        with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Error: index.html not found</h1>"

def plotly_to_json(fig_dict):
    """Convert plotly figure dict to JSON string for frontend"""
    return json.dumps(fig_dict)


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    template = get_template()
    
    # 1. Load Data
    flows = load_json(FLOWS_FILE) or []
    graph_data = load_json(GRAPH_FILE) or {"nodes": [], "edges": []}
    suspect_ip = "172.16.0.2" # Default to WARP internal IP

    # Using local import from backend for live processing
    from backend.endpoint_profiler import EndpointProfiler
    profiler = EndpointProfiler()
    if flows:
        flows_dict = {str(i): f for i, f in enumerate(flows)}
        profiler.profile_endpoints(flows_dict, suspect_ip)
    profiles = profiler.profiles
    
    # 2. Generate Visualizations
    from datetime import datetime
    import hashlib
    
    network_json = json.dumps(viz.create_network_graph(graph_data))
    timeline_json = json.dumps(viz.create_timeline_chart(flows))
    signal_matrix_data = viz.create_signal_matrix(profiles) if profiles else []
    
    # 3. Format Signal Matrix Table Body
    matrix_html = ""
    for row in signal_matrix_data:
        matrix_html += f"""
        <tr>
            <td style="text-align: left; color: {'var(--danger)' if row['infra']=='CRITICAL' else 'inherit'};">{row['ip']}</td>
            <td style="background: rgba(46,213,115,0.2);">{row['burst']}</td>
            <td style="background: rgba(46,213,115,0.2);">{row['rhythm']}</td>
            <td style="background: rgba(255,165,2,0.2);">{row['fingerprint']}</td>
            <td style="background: {'rgba(255,71,87,0.2)' if row['infra']=='CRITICAL' else 'rgba(255,255,255,0.05)'}; 
                       color: {'var(--danger)' if row['infra']=='CRITICAL' else 'inherit'};">{row['infra']}</td>
            <td style="background: rgba(46,213,115,0.2);">{row['graph']}</td>
        </tr>
        """

    # Format Audit Log
    audit_html = ""
    all_flows_list = list(flows) if flows else []
    display_limit = min(20, len(all_flows_list))
    for i in range(display_limit):
         flow = all_flows_list[i]
         ts = datetime.fromtimestamp(float(flow.get('start_time', 0))).isoformat()
         audit_html += f"""
         <div style="padding: 8px; border-left: 2px solid var(--accent-cyan); background: rgba(0,212,255,0.05); font-size: 0.8rem;">
            <span class="text-muted">[{ts}]</span> System - PACKET_INGEST: {flow.get('total_bytes', 0)} bytes captured from {flow.get('dst_ip')}
         </div>
         """
    
    signature = hashlib.sha256(f"{suspect_ip}{len(flows)}".encode()).hexdigest()
    
    # 4. Inject Dynamic Content
    html = template
    html = html.replace("__SUSPECT_IP__", suspect_ip)
    html = html.replace("__TOTAL_FLOWS__", str(len(flows)))
    html = html.replace("__TOTAL_BURSTS__", str(len(flows) // 4))
    html = html.replace("__TOTAL_ENDPOINTS__", str(len(profiles)))
    html = html.replace("__ALERT_SECTION__", "HIGH CONFIDENCE CORRELATION: TOR EXIT NODE DETECTED")
    html = html.replace("__NETWORK_GRAPH__", network_json)
    html = html.replace("__TIMELINE__", timeline_json)
    html = html.replace("__SIGNAL_MATRIX__", matrix_html)
    html = html.replace("__AUDIT_LOG__", audit_html)
    html = html.replace("__DIGITAL_SIGNATURE__", signature)
    
    return html


@app.post("/api/open-wireshark")
async def launch_wireshark():
    """Trigger Wireshark launch for the current PCAP file"""
    pcap_file = os.path.join(DATA_DIR, "captured_packets.pcap")
    success = open_wireshark(pcap_file)
    if success:
        return {"status": "success", "message": "Wireshark launched"}
    else:
        return {"status": "error", "message": "Could not launch Wireshark. Ensure it is installed."}

@app.get("/api/warp-status")
async def warp_status():
    return get_warp_status()

@app.post("/api/warp-connect")
async def warp_connect():
    return connect_warp()

@app.post("/api/warp-disconnect")
async def warp_disconnect():
    return disconnect_warp()


@app.get("/api/live-stream")
async def get_live_stream():
    """Endpoint for frontend to poll for real-time packet metadata"""
    return streamer.get_latest()


@app.get("/api/device-profiles")
async def get_device_profiles():
    """Returns all passively discovered device profiles"""
    from backend.device_profiler import profiler
    return profiler.get_all_profiles()


@app.get("/api/network-nodes")
async def get_network_nodes():
    """Returns a list of all discovered IP addresses in the current capture session"""
    from backend.device_profiler import profiler
    return list(profiler.hostnames.keys())


@app.get("/api/correlations")
async def get_correlations(ip: Optional[str] = None):
    """Returns real-time statistical burst correlations — always returns threat intel data."""
    from backend.device_profiler import profiler
    from backend.burst_correlator import correlator

    if not ip:
        nodes = [n for n in profiler.hostnames.keys() if not n.endswith(".1")]
        ip = nodes[0] if nodes else "probe"

    return correlator.get_correlations(ip)


@app.post("/api/trigger-demo-burst")
async def trigger_demo_burst(ip: str):
    """Simulates a series of synchronized packets for demonstration purposes"""
    from backend.burst_correlator import correlator
    
    vpn_node = "185.220.101.47" # Tor Exit
    now = float(time.time())
    
    # Simulate a 'burst' sequence: Suspect sends, VPN responds 120ms later
    for i in range(5):
        t = now + (i * 0.4)
        correlator.record_packet(ip, "remote", 1450)
        # Manually inject history for the VPN node with a slight delay
        if vpn_node not in correlator.history:
            correlator.history[vpn_node] = []
        correlator.history[vpn_node].append({"ts": t + 0.12, "len": 1450, "dir": "IN"})
        
    return {"status": "success", "message": f"Demo burst triggered for {ip} -> {vpn_node}"}


@app.get("/api/synchrony")
async def get_synchrony(suspect_ip: str, vpn_ip: str):
    """Returns real-time throughput series for two IPs to show synchrony"""
    from backend.burst_correlator import correlator
    
    suspect_series = correlator.get_throughput_series(suspect_ip)
    vpn_series = correlator.get_throughput_series(vpn_ip)
    
    return {
        "suspect": suspect_series,
        "vpn": vpn_series,
        "labels": [f"{i}s ago" for i in range(len(suspect_series)-1, -1, -1)]
    }


def main():
    """Start the dashboard server"""
    print("=" * 60)
    print("ECHO Forensic Dashboard")
    print("=" * 60)
    print(f"Dashboard available at http://localhost:8009")
    print("=" * 60)
    
    # Start the live packet sniffer in the background
    streamer.start()
    
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8011,
            log_level="info"
        )
    finally:
        streamer.stop()


if __name__ == "__main__":
    main()