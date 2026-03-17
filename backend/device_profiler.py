import logging
import time
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class DeviceProfiler:
    def __init__(self):
        # Explicitly typed storage to satisfy strict linters
        self.hostnames: Dict[str, str] = {}
        self.os_types: Dict[str, str] = {}
        self.confidences: Dict[str, int] = {}
        self.manufacturers: Dict[str, str] = {}
        self.tags_list: Dict[str, List[str]] = {}
        self.vpn_ports = {500, 4500, 1194, 51820, 1723}

    def profile_packet(self, packet):
        """Analyzes a packet to extract device identifiers with explicit typing"""
        from scapy.all import IP, TCP, UDP, NBNSQueryRequest, DHCP, DNSQR
        
        if not packet.haslayer(IP):
            return

        ip_src = str(packet[IP].src)
        if ip_src not in self.hostnames:
            self.hostnames[ip_src] = "Unknown"
            self.os_types[ip_src] = "Detecting..."
            self.confidences[ip_src] = 0
            self.manufacturers[ip_src] = "Scanning"
            self.tags_list[ip_src] = []

        # 1. Hostname Discovery via NBNS (NetBIOS)
        if packet.haslayer(NBNSQueryRequest):
            try:
                name = str(packet[NBNSQueryRequest].QUESTION_NAME.decode().strip())
                if name and name not in self.hostnames[ip_src]:
                    self.hostnames[ip_src] = name
                    self.confidences[ip_src] += 40
            except: pass

        # 2. Hostname Discovery via DHCP
        if packet.haslayer(DHCP):
            from scapy.all import DHCP
            options = packet[DHCP].options
            for opt in options:
                if isinstance(opt, tuple):
                    if opt[0] == 'hostname':
                        self.hostnames[ip_src] = str(opt[1].decode() if isinstance(opt[1], bytes) else opt[1])
                        self.confidences[ip_src] += 50
                    elif opt[0] == 'vendor_class_id':
                        self.manufacturers[ip_src] = str(opt[1].decode() if isinstance(opt[1], bytes) else opt[1])

        # 3. OS Fingerprinting via TCP Window Size & TTL
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            win = packet[TCP].window
            ttl = packet[IP].ttl
            if win == 64240 and ttl == 128:
                self.os_types[ip_src] = "Windows 10/11"
                self.confidences[ip_src] += 20
            elif win == 65535 and ttl == 64:
                self.os_types[ip_src] = "iOS / macOS"
                self.confidences[ip_src] += 20
                if "Mobile" not in self.tags_list[ip_src]:
                    self.tags_list[ip_src].append("Mobile")
            elif ttl == 64:
                self.os_types[ip_src] = "Linux / Android"
                self.confidences[ip_src] += 15

        # 4. mDNS / LLMNR
        if packet.haslayer(UDP) and (packet[UDP].dport == 5353 or packet[UDP].dport == 5355):
            if packet.haslayer(DNSQR):
                try:
                    name = str(packet[DNSQR].qname.decode().strip('.'))
                    if ".local" in name:
                        clean_name = name.replace(".local", "")
                        if clean_name not in self.hostnames[ip_src]:
                            self.hostnames[ip_src] = clean_name
                            self.confidences[ip_src] += 30
                except: pass

        # 5. VPN/Tunnel Detection
        if packet.haslayer(UDP):
            if packet[UDP].sport in self.vpn_ports or packet[UDP].dport in self.vpn_ports:
                if "VPN_TUNNEL" not in self.tags_list[ip_src]:
                    self.tags_list[ip_src].append("VPN_TUNNEL")
                    self.confidences[ip_src] = min(100, self.confidences[ip_src] + 25)
        elif packet.haslayer(TCP):
             if packet[TCP].sport == 443 or packet[TCP].dport == 443:
                 # Check for high randomness in payload if Raw is present (TBD)
                 pass

    def get_profile(self, ip: str) -> Dict[str, Any]:
        """Returns the combined profile for an IP"""
        if ip not in self.hostnames: return {}
        return {
            "hostname": self.hostnames[ip],
            "os": self.os_types[ip],
            "confidence": self.confidences[ip],
            "manufacturer": self.manufacturers[ip],
            "tags": self.tags_list[ip]
        }

    def get_all_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Returns all profiles"""
        return {ip: self.get_profile(ip) for ip in self.hostnames}

# Singleton
profiler = DeviceProfiler()
