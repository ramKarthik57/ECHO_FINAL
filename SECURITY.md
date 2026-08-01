# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in ECHO, please report it responsibly:

1. **Email**: Open a private GitHub security advisory at:
   `https://github.com/ramKarthik57/ECHO_FINAL/security/advisories/new`

2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - (Optional) Suggested fix

3. **Response time**: We aim to respond within **72 hours** and provide a fix within **7 days** for critical issues.

---

## Security Design Principles

ECHO is built with the following security principles:

### No Content Decryption
ECHO **never** decrypts or attempts to access the content of encrypted communications. It works exclusively with network metadata (timestamps, IP addresses, packet sizes, ports).

### Minimal Data Retention
- Raw PCAP files should be stored with appropriate access controls
- The SQLite database contains investigation audit trails
- Sensitive data (investigator credentials, warrant numbers) are stored locally and never transmitted externally

### Access Control
- The REST API (`localhost:8000`) is designed for local/trusted network use only
- Do not expose the API or dashboard to the public internet without proper authentication and TLS
- Investigator authentication is enforced via badge number and warrant verification

### Network Isolation
- Run ECHO on isolated, dedicated forensic workstations
- Use VLANs or air-gapped environments for sensitive investigations
- The CORS policy (`allow_origins=["*"]`) should be restricted in production deployments

---

## Known Limitations

- **No authentication layer**: The current API has no token-based authentication. Add a reverse proxy with authentication for multi-user environments.
- **SQLite database**: Not suitable for high-concurrency multi-investigator setups. Consider PostgreSQL for production.
- **PCAP data sensitivity**: Captured PCAP files may contain sensitive metadata and should be stored with restricted filesystem permissions.

---

## Legal Notice

ECHO is designed for **lawful forensic investigations** conducted under appropriate legal authority (warrants, court orders). Unauthorized network capture or interception may violate local laws. The authors assume no liability for misuse of this software.
