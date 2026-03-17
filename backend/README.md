# ECHO - Encrypted Communication Heuristic Observer

A forensic investigation tool for analyzing encrypted communication metadata to identify behavioral patterns and communication relationships without decrypting content.

## Overview

ECHO is a lawful, non-intrusive forensic tool that analyzes network-level metadata from encrypted communications. It identifies probable communication partners through temporal correlation, burst synchronization, and behavioral fingerprinting.

**Key Features:**
- Network packet capture and metadata extraction
- Traffic flow and session analysis
- Burst detection and temporal correlation
- Endpoint behavioral profiling
- Communication relationship graph building
- Interactive web dashboard for investigation insights

**Important:** This tool does NOT decrypt message content. It analyzes only network metadata.

---

## Installation

### Prerequisites
- Python 3.8+
- Root/admin privileges (for packet capture)
- Linux/macOS/Windows with network access

### Setup

1. **Clone or download the project**
```bash
cd echo-forensic-tool
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Create data directory** (auto-created on first run)
```bash
mkdir -p data
```

---

## Quick Start

### Option 1: Full Analysis Pipeline

Run the complete analysis in one command:
```bash
# 1. Capture packets (requires sudo)
sudo python3 backend/packet_capture.py

# 2. Run full analysis
python3 -c "
from backend.metadata_extractor import MetadataExtractor
from backend.flow_builder import FlowBuilder
from backend.burst_analyzer import BurstAnalyzer
from backend.endpoint_profiler import EndpointProfiler
from backend.graph_builder import GraphBuilder

# Extract metadata
extractor = MetadataExtractor()
metadata = extractor.extract_from_pcap()
extractor.save_metadata()

# Build flows
builder = FlowBuilder()
flows = builder.build_flows(metadata)
builder.save_flows()

# Detect bursts
analyzer = BurstAnalyzer()
bursts = analyzer.detect_bursts_in_flows(flows)

# Profile endpoints (replace with actual suspect IP)
suspect_ip = list(flows.values())[0]['src_ip']
profiler = EndpointProfiler()
profiles = profiler.profile_endpoints(flows, suspect_ip)
profiler.save_profiles()

# Find correlations
correlations = analyzer.find_correlated_bursts(suspect_ip)

# Build graph
graph_builder = GraphBuilder()
graph = graph_builder.build_graph(flows, profiles, suspect_ip, correlations)
graph_builder.save_graph()
"

# 3. Launch dashboard
python3 dashboard/app.py
```

Then open http://localhost:8001 in your browser.

### Option 2: API Server

Start the REST API server:
```bash
python3 backend/api_server.py
```

API available at http://localhost:8000

Run analysis via API:
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"suspect_ip": "192.168.1.100"}'
```

---

## Usage Guide

### Step 1: Packet Capture

Capture network traffic (requires root):
```bash
sudo python3 backend/packet_capture.py
```

Or use an existing PCAP file by placing it in `data/captured_packets.pcap`

### Step 2: Extract Metadata
```bash
python3 backend/metadata_extractor.py
```

Extracts packet metadata (timestamps, IPs, ports, sizes) without content.

### Step 3: Build Flows
```bash
python3 backend/flow_builder.py
```

Groups packets into bidirectional communication sessions.

### Step 4: Detect Bursts
```bash
python3 backend/burst_analyzer.py
```

Identifies message bursts and temporal correlations.

### Step 5: Profile Endpoints
```bash
python3 backend/endpoint_profiler.py
```

Creates behavioral profiles for remote endpoints.

### Step 6: Build Graph
```bash
python3 backend/graph_builder.py
```

Constructs communication relationship graph.

### Step 7: View Dashboard
```bash
python3 dashboard/app.py
```

Opens interactive dashboard at http://localhost:8001

---

## Configuration

Edit `utils/config.py` to customize:
```python
# Packet Capture
CAPTURE_INTERFACE = "eth0"  # Network interface
PACKET_COUNT = 1000         # Number of packets
CAPTURE_TIMEOUT = 60        # Capture duration (seconds)

# Flow Analysis
FLOW_TIMEOUT = 300          # Flow inactivity timeout
BURST_THRESHOLD = 2.0       # Burst detection threshold
MIN_BURST_PACKETS = 3       # Minimum packets per burst

# Correlation
CORRELATION_WINDOW = 5.0    # Temporal correlation window
MIN_CORRELATION_SCORE = 0.6 # Minimum correlation score
```

---

## Architecture

### Backend Modules

1. **packet_capture.py** - Captures network packets using Scapy
2. **metadata_extractor.py** - Extracts metadata from packets
3. **flow_builder.py** - Groups packets into communication flows
4. **burst_analyzer.py** - Detects bursts and correlations
5. **endpoint_profiler.py** - Profiles remote endpoints
6. **graph_builder.py** - Builds relationship graphs
7. **api_server.py** - FastAPI REST server

### Dashboard

- **app.py** - Web dashboard server
- **visualization.py** - Plotly chart generation

### Data Flow
```
PCAP → Metadata → Flows → Bursts → Profiles → Graph → Dashboard
```

---

## API Endpoints

- `GET /` - API info
- `POST /analyze` - Run full analysis
- `GET /flows` - Get communication flows
- `GET /bursts` - Get detected bursts
- `GET /endpoints` - Get endpoint profiles
- `GET /endpoints/ranked` - Get ranked endpoints
- `GET /correlations` - Get burst correlations
- `GET /graph` - Get relationship graph
- `GET /status` - Check analysis status

---

## Legal & Ethical Use

⚠️ **IMPORTANT:** This tool is designed for lawful forensic investigation only.

**Authorized Use:**
- Law enforcement with proper warrant
- Corporate security investigations with authorization
- Research and educational purposes with consent

**Prohibited Use:**
- Unauthorized surveillance
- Mass data collection
- Privacy violations
- Illegal monitoring

**Privacy by Design:**
- No content decryption
- Metadata-only analysis
- Warrant-required deployment
- Transparent and auditable

---

## Example Investigation Scenario

**Scenario:** Investigating suspected dark web communications

1. **Deploy:** Install ECHO on suspect's gateway with warrant
2. **Capture:** Collect 24 hours of network traffic
3. **Analyze:** Run full analysis pipeline
4. **Identify:** Dashboard reveals:
   - High-frequency communication with specific IP
   - Regular timing patterns (daily, 45-minute sessions)
   - Burst synchronization indicating real-time chat
   - IP linked to known VPS provider used by criminal groups

5. **Result:** High-probability link to criminal infrastructure

---

## Troubleshooting

**"Permission denied" during packet capture**
```bash
# Run with sudo
sudo python3 backend/packet_capture.py
```

**"No flows found" error**
```bash
# Ensure PCAP file exists
ls -lh data/captured_packets.pcap

# Check if metadata was extracted
python3 backend/metadata_extractor.py
```

**Dashboard shows empty charts**
```bash
# Verify all analysis steps completed
python3 backend/flow_builder.py
python3 backend/endpoint_profiler.py
python3 backend/graph_builder.py
```

---

## Technology Stack

- **Packet Analysis:** Scapy
- **Data Processing:** Pandas, NumPy
- **Graph Analysis:** NetworkX
- **API:** FastAPI, Uvicorn
- **Visualization:** Plotly
- **Storage:** JSON, SQLite

---

## Contributing

This is a prototype hackathon project. Contributions welcome:

1. Fork the repository
2. Create feature branch
3. Implement improvements
4. Submit pull request

---

## License

Educational and research use only. See LICENSE file.

---

## Acknowledgments

Based on the ECHO framework for behavioral deanonymization of encrypted communications through metadata analysis.

**References:**
- Traffic analysis techniques
- Temporal correlation methods
- Network forensics best practices

---

## Contact

For questions or support, please open an issue.

---

**Disclaimer:** This tool is provided for lawful forensic investigation purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations.