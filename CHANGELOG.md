# Changelog

All notable changes to **ECHO** will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-03-17

### Added
- Initial release of ECHO - Encrypted Communication Heuristic Observer
- **Packet Capture**: Live network capture via Scapy and PCAP file import
- **Metadata Extraction**: Non-intrusive extraction of packet timing, IPs, ports, and sizes
- **Flow Builder**: Bidirectional communication flow construction and session tracking
- **Burst Analyzer**: Traffic burst detection using inter-packet gap analysis
- **Burst Correlator**: Temporal synchronization detection between endpoint burst patterns
- **Endpoint Profiler**: Behavioral fingerprinting — active hours, port preferences, session durations
- **Device Profiler**: Device-level traffic characterization
- **Graph Builder**: Communication relationship graph using NetworkX
- **REST API**: FastAPI-based backend with endpoints for analysis, flows, bursts, endpoints, and correlations
- **Web Dashboard**: Interactive investigation interface with Plotly charts
- **Database**: SQLite-backed audit trail for investigators, warrants, and cases
- **Demo Generator**: Utility to generate synthetic PCAP data for testing
- **Wireshark Bridge**: Integration with tshark/Wireshark for additional capture capabilities
- **WARP Bridge**: Cloudflare WARP tunnel integration for VPN-aware capture
- **Full Pipeline Runner**: `run_analysis.py` for end-to-end analysis in one command
- Project documentation and backend README

---

## [Unreleased]

### Planned
- [ ] Authentication middleware for REST API (JWT/API key)
- [ ] Docker containerization for easy deployment
- [ ] GitHub Actions CI/CD pipeline with automated tests
- [ ] PostgreSQL support for multi-user environments
- [ ] PCAP file upload via dashboard UI
- [ ] GeoIP enrichment for endpoint profiles
- [ ] Export reports as PDF
- [ ] Packet streaming via WebSocket for real-time dashboard updates
- [ ] Plugin system for custom analyzers
- [ ] Dark/light mode toggle in dashboard
