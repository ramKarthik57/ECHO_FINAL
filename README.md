<div align="center">

# 🔭 ECHO
### *Encrypted Communication Heuristic Observer*

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)](https://github.com/ramKarthik57/ECHO_FINAL)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)](https://github.com/ramKarthik57/ECHO_FINAL)

> **A lawful, privacy-preserving forensic investigation tool for analyzing encrypted network traffic metadata — without ever decrypting message content.**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [API Reference](#-api-reference)
- [Dashboard](#-dashboard)
- [How It Works](#-how-it-works)
- [Configuration](#-configuration)
- [Contributing](#-contributing)
- [Legal and Ethical Notice](#-legal--ethical-notice)
- [License](#-license)

---

## 🔭 Overview

**ECHO** (Encrypted Communication Heuristic Observer) is a forensic investigation tool designed for law enforcement, cybersecurity professionals, and researchers. It analyzes **network-level metadata** from encrypted communications to identify:

- Behavioral patterns and communication rhythms
- Probable communication partners (without decryption)
- Traffic burst synchronization indicating active conversations
- Endpoint behavioral fingerprints

> ECHO does NOT decrypt any message content. It works exclusively on network metadata (timestamps, IP addresses, packet sizes, port numbers) — fully compliant with lawful interception standards.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 📦 **Packet Capture** | Live network capture via Scapy or PCAP file import |
| 🔍 **Metadata Extraction** | Extract timing, IPs, ports, and sizes without content access |
| 🌊 **Flow Analysis** | Build and analyze bidirectional communication flows |
| 💥 **Burst Detection** | Identify traffic bursts indicative of messaging activity |
| ⏱️ **Temporal Correlation** | Find synchronized bursts between endpoints |
| 🧠 **Endpoint Profiling** | Behavioral fingerprinting of network endpoints |
| 🕸️ **Graph Building** | Construct communication relationship graphs |
| 📊 **Interactive Dashboard** | Real-time web-based investigation interface |
| 🗄️ **Database Storage** | Persistent SQLite storage for investigation audit trails |
| 🔌 **REST API** | Full-featured FastAPI backend for integration |

---

## 🏗️ Architecture

```
+-------------------------------------------------------------+
|                        ECHO SYSTEM                          |
+-----------------+---------------------+---------------------+
|   DATA LAYER    |   ANALYSIS ENGINE   |   PRESENTATION      |
|                 |                     |                     |
| PacketCapture   | MetadataExtractor   | Web Dashboard       |
| LiveCapture     | FlowBuilder         | REST API            |
| PCAP Import     | BurstAnalyzer       | Plotly Charts       |
| Database        | BurstCorrelator     | Network Graph       |
|                 | EndpointProfiler    |                     |
|                 | GraphBuilder        |                     |
+-----------------+---------------------+---------------------+
```

### Analysis Pipeline

```
Raw Network Traffic
        |
        v
  +--------------+
  | Packet Layer |  <- Scapy / PyShark / PCAP
  +------+-------+
         |
         v
  +--------------+
  |  Metadata    |  <- Timestamps, IPs, Ports, Sizes
  |  Extraction  |
  +------+-------+
         |
         v
  +--------------+
  | Flow Builder |  <- Session grouping, bidirectional flows
  +------+-------+
         |
         v
  +--------------+
  |    Burst     |  <- Inter-packet gaps, burst windows
  |   Analyzer   |
  +------+-------+
         |
         v
  +--------------+
  |  Endpoint    |  <- Behavioral fingerprinting, port profiles
  |  Profiler    |
  +------+-------+
         |
         v
  +--------------+
  |    Graph     |  <- Communication relationship graph
  |   Builder    |
  +------+-------+
         |
         v
  Interactive Dashboard / REST API
```

---

## 📁 Project Structure

```
ECHO_FINAL/
├── backend/                       # Core analysis engine
│   ├── api_server.py              # FastAPI REST API server
│   ├── packet_capture.py          # PCAP-based packet capture
│   ├── live_capture.py            # Real-time network capture
│   ├── metadata_extractor.py      # Packet metadata extraction
│   ├── flow_builder.py            # Communication flow construction
│   ├── burst_analyzer.py          # Traffic burst detection
│   ├── burst_correlator.py        # Temporal burst correlation
│   ├── endpoint_profiler.py       # Endpoint behavioral profiling
│   ├── device_profiler.py         # Device-level profiling
│   ├── graph_builder.py           # Communication graph builder
│   ├── packet_streamer.py         # Real-time packet streaming
│   ├── database.py                # SQLite database manager
│   └── README.md                  # Backend documentation
│
├── dashboard/                     # Web interface
│   ├── app.py                     # Dashboard web server
│   ├── echo_dashboard.html        # Main dashboard UI
│   ├── index_template.html        # HTML template
│   └── visualization.py           # Plotly chart generation
│
├── utils/                         # Shared utilities
│   ├── config.py                  # Configuration constants
│   ├── helpers.py                 # Common helper functions
│   ├── network_helper.py          # Network utility functions
│   ├── warp_bridge.py             # Cloudflare WARP integration
│   ├── wireshark_bridge.py        # Wireshark/tshark bridge
│   └── generate_demo_pcap.py      # Demo PCAP generator
│
├── data/                          # Runtime data directory
│   ├── captured_packets.pcap      # Captured network packets
│   ├── metadata.json              # Extracted packet metadata
│   ├── flows.json                 # Built communication flows
│   ├── correlations.json          # Burst correlations
│   ├── endpoint_profiles.json     # Endpoint behavioral profiles
│   ├── graph.json                 # Communication graph data
│   └── echo_forensic.db           # SQLite investigation database
│
├── tests/                         # Test suite
│   ├── test_metadata_extractor.py
│   ├── test_flow_builder.py
│   ├── test_burst_analyzer.py
│   └── test_api.py
│
├── run_analysis.py                # One-command full pipeline runner
├── requirements.txt               # Python dependencies
├── .gitignore                     # Git ignore rules
├── CONTRIBUTING.md                # Contribution guidelines
├── SECURITY.md                    # Security policy
├── LICENSE                        # MIT License
└── README.md                      # This file
```

---

## ⚙️ Installation

### Prerequisites

- **Python** 3.8 or higher
- **pip** package manager
- **Root/Administrator** privileges (for live packet capture only)
- **Npcap** (Windows) or **libpcap** (Linux/macOS) for packet capture

### Step 1: Clone the Repository

```bash
git clone https://github.com/ramKarthik57/ECHO_FINAL.git
cd ECHO_FINAL
```

### Step 2: Create a Virtual Environment (Recommended)

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows
python -m venv .venv
.venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Generate Demo Data (Optional)

If you don't have a PCAP file ready:

```bash
python utils/generate_demo_pcap.py
```

---

## 🚀 Quick Start

### Option A: Full Pipeline (Recommended)

```bash
python run_analysis.py --suspect-ip 192.168.1.100
python dashboard/app.py
# Open: http://localhost:8001
```

### Option B: REST API Mode

```bash
python backend/api_server.py
# API at: http://localhost:8000
# Docs at: http://localhost:8000/docs

curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"suspect_ip": "192.168.1.100"}'
```

### Option C: Step-by-Step

```bash
# 1. Capture packets (requires root/admin)
sudo python backend/packet_capture.py

# 2. Run analysis pipeline
python run_analysis.py

# 3. Launch dashboard
python dashboard/app.py
```

---

## 📖 Usage Guide

### Packet Capture

**Live capture** (requires root/admin):
```bash
sudo python backend/packet_capture.py
```

**Import existing PCAP file** by placing it at `data/captured_packets.pcap`.

**Generate demo PCAP:**
```bash
python utils/generate_demo_pcap.py
```

### Metadata Extraction

```python
from backend.metadata_extractor import MetadataExtractor

extractor = MetadataExtractor()
metadata = extractor.extract_from_pcap()
extractor.save_metadata()
print(f"Extracted {len(metadata)} packet records")
```

Extracted fields: `timestamp`, `src_ip`, `dst_ip`, `protocol`, `packet_size`, `src_port`, `dst_port`.

### Flow Building

```python
from backend.flow_builder import FlowBuilder
from utils.helpers import load_json

metadata = load_json("data/metadata.json")
builder = FlowBuilder()
flows = builder.build_flows(metadata)
builder.save_flows()
```

### Burst Analysis

```python
from backend.burst_analyzer import BurstAnalyzer
from utils.helpers import load_json

flows = load_json("data/flows.json")
analyzer = BurstAnalyzer()
bursts = analyzer.detect_bursts_in_flows(flows)
correlations = analyzer.find_correlated_bursts("192.168.1.100")
```

---

## 🔌 API Reference

The REST API is served at `http://localhost:8000`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | API info |
| `POST` | `/analyze` | Run full forensic pipeline |
| `GET` | `/flows` | Get all communication flows |
| `GET` | `/bursts` | Get detected traffic bursts |
| `GET` | `/endpoints` | Get endpoint profiles |
| `GET` | `/graph` | Get communication graph |
| `GET` | `/correlations` | Get burst correlations |
| `POST` | `/investigators` | Register investigator |
| `POST` | `/warrants` | Create investigation warrant |
| `POST` | `/login` | Investigator login |

**Interactive docs**: http://localhost:8000/docs

---

## 📊 Dashboard

The web dashboard at `http://localhost:8001` provides:

- **Traffic Overview** — Packet volume and protocol breakdown
- **Flow Inspector** — Interactive table of communication sessions
- **Burst Timeline** — Visual burst activity timeline
- **Correlation Map** — Heatmap of burst correlations
- **Endpoint Profiles** — Behavioral fingerprints
- **Communication Graph** — Interactive network relationship graph
- **Investigation Log** — Warrant and investigator management

---

## 🧠 How It Works

### Traffic Burst Detection

ECHO identifies "bursts" by analyzing inter-packet timing gaps. When the gap exceeds `BURST_THRESHOLD_SECONDS`, a new burst begins. Burst patterns from encrypted messaging apps (Signal, WhatsApp, Telegram) cluster at characteristic intervals.

### Temporal Correlation

Two endpoints are flagged as **probable communicators** when their burst patterns synchronize within a correlation window:

```
For each burst B_A from Endpoint A:
  For each burst B_B from Endpoint B:
    if |timestamp(B_A) - timestamp(B_B)| < CORRELATION_WINDOW:
      flag A <--> B as correlated
```

### Behavioral Fingerprinting

Each endpoint is profiled across:
- Active hours distribution
- Preferred destination ports
- Average session duration
- Packet size distribution
- Burst frequency and intensity

---

## 🛠️ Configuration

Edit `utils/config.py`:

```python
# Network Capture
NETWORK_INTERFACE = "eth0"
CAPTURE_DURATION = 300              # 5 minutes
PCAP_FILE = "data/captured_packets.pcap"

# Analysis Thresholds
BURST_THRESHOLD_SECONDS = 2.0
CORRELATION_WINDOW_SECONDS = 5.0
MIN_BURST_PACKETS = 3

# Server Ports
API_PORT = 8000
DASHBOARD_PORT = 8001
```

---

## 🤝 Contributing

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/your-feature`
3. **Commit** your changes: `git commit -m 'Add your feature'`
4. **Push** to the branch: `git push origin feature/your-feature`
5. **Open** a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## ⚖️ Legal & Ethical Notice

> **This tool is intended for lawful forensic investigations only.**

- ECHO **never decrypts** or accesses communication content
- All analyses must be conducted under appropriate **legal authority** (warrants, court orders)
- Designed to comply with lawful interception standards
- Unauthorized network interception may be illegal in your jurisdiction
- Authors assume no liability for misuse

**Use responsibly. Use legally.**

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [Scapy](https://scapy.net/) — Packet manipulation library
- [FastAPI](https://fastapi.tiangolo.com/) — Modern web framework
- [Plotly](https://plotly.com/) — Interactive visualization
- [NetworkX](https://networkx.org/) — Graph analysis
- [PyShark](https://github.com/KimiNewt/pyshark) — Wireshark Python bridge

---

<div align="center">

**Built for forensic investigators who respect privacy.**

*ECHO — See the patterns. Not the words.*

</div>
