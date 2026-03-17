"""
Configuration settings for ECHO forensic tool
"""
import os

# Packet Capture Settings
CAPTURE_INTERFACE = "CloudflareWARP"  # Network interface to capture from (Virtual adapter for WARP)
CAPTURE_FILTER = "tcp or udp"  # BPF filter
PACKET_COUNT = 1000  # Number of packets to capture (0 = unlimited)
CAPTURE_TIMEOUT = 60  # Seconds

# Flow Analysis Settings
FLOW_TIMEOUT = 300  # Seconds of inactivity before flow expires
BURST_THRESHOLD = 2.0  # Seconds - gap between packets to define burst boundary
MIN_BURST_PACKETS = 3  # Minimum packets to consider a burst

# Timing Correlation Settings
CORRELATION_WINDOW = 5.0  # Seconds - window to look for response bursts
MIN_CORRELATION_SCORE = 0.6  # Minimum score to flag as correlated

# File Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
PCAP_FILE = os.path.join(DATA_DIR, "captured_packets.pcap")
FLOWS_FILE = os.path.join(DATA_DIR, "flows.json")
METADATA_FILE = os.path.join(DATA_DIR, "metadata.json")
GRAPH_FILE = os.path.join(DATA_DIR, "graph.json")

# API Settings
API_HOST = "0.0.0.0"
API_PORT = 8000

# Visualization Settings
TIMELINE_HEIGHT = 600
GRAPH_HEIGHT = 700

# Create data directory if it doesn't exist
os.makedirs(DATA_DIR, exist_ok=True)