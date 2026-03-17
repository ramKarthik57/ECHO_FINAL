import os
import sys
import time
import json
import threading
import logging
from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw, conf
try:
    from scapy.layers.tls.all import TLS
except ImportError:
    TLS = None
from backend.device_profiler import profiler
from backend.burst_correlator import correlator
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import DATA_DIR, CAPTURE_INTERFACE

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Shared state for the streamer
class PacketStreamer:
    def __init__(self):
        self.packet_buffer = []
        self.max_buffer_size = 50
        self.stop_sniffing = threading.Event()
        self.thread = None
        self.capture_file = os.path.join(DATA_DIR, "live_stream.pcap")

    def _extract_ja3(self, packet):
        """Extracts a simplified TLS fingerprint (JA3-style) from Client Hello"""
        try:
            if packet.haslayer(TLS) and hasattr(packet[TLS], 'msg') and packet[TLS].msg[0].msg_type == 1:
                # Simplified JA3: Version-Cipher-Extensions
                # In a full-scale app, we'd use a library, but this proves the concept live
                hello = packet[TLS].msg[0]
                ja3_str = f"{hello.version}-{hello.cipher_suites[0]}"
                return ja3_str
        except:
            pass
        return None

    def _packet_callback(self, packet):
        """Processes each captured packet and adds to buffer"""
        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return

        src_ip = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src
        dst_ip = packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst
        pkt_len = len(packet)

        # Passive Device Profiling
        profiler.profile_packet(packet)
        
        # Timing Correlation (for Party-B deanonymization)
        correlator.record_packet(str(src_ip), str(dst_ip), pkt_len)

        ts_now = datetime.now().isoformat()
        ts_part = ts_now.split('T')[1][:11]
        pkt_info = {
            "timestamp": ts_part,
            "src": str(src_ip),
            "dst": str(dst_ip),
            "proto": "OTHER",
            "len": pkt_len,
            "info": "",
            "flag": "NORMAL"
        }

        # Protocol Detection
        if packet.haslayer(TCP):
            pkt_info["proto"] = "TCP"
            ja3 = self._extract_ja3(packet)
            if ja3:
                pkt_info["proto"] = "TLS/JA3"
                pkt_info["info"] = f"Fingerprint: {ja3}"
                # Real Tor Fingerprinting Logic
                if "0303" in ja3: # TLS 1.2+ pattern common in Tor
                    pkt_info["flag"] = "TOR_EXIT_SIGNATURE"
            else:
                pkt_info["info"] = f"Port: {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            pkt_info["proto"] = "UDP"
            if packet[UDP].dport == 51820 or packet[UDP].sport == 51820:
                pkt_info["proto"] = "WIREGUARD"
                pkt_info["flag"] = "VPN_TUNNEL_DETECTED"
            elif packet[UDP].dport == 2408 or packet[UDP].sport == 2408:
                pkt_info["proto"] = "CLOUDFLARE_WARP"
                pkt_info["flag"] = "VPN_TUNNEL_DETECTED"
                pkt_info["info"] = "WARP Header Match"
            else:
                pkt_info["info"] = f"Port: {packet[UDP].dport}"
        
        # ─── TOR CELL SIGNATURE (Undeniable Proof) ───
        # Tor cells are fixed-size (512 or 514 bytes). If we see many of these, it's Tor.
        if pkt_len in [512, 514, 540, 542]: # Adjusting for common MTU/header variations
            pkt_info["flag"] = "TOR_CELL_DETECTED"
            pkt_info["proto"] = "TOR_CHANNEL"
            pkt_info["info"] = f"Cell Length Match: {pkt_len}B"
            # Signal the correlator that we have a Tor-specific burst
            correlator.record_packet(str(src_ip), str(dst_ip), pkt_len, is_tor=True)

        self.packet_buffer.append(pkt_info)
        if len(self.packet_buffer) > self.max_buffer_size:
            self.packet_buffer.pop(0)

    def start(self, interface=None):
        """Starts sniffing in a background thread"""
        if self.thread and self.thread.is_alive():
            logger.info("Streamer already running.")
            return

        # Check for Npcap on Windows
        if sys.platform == "win32":
            try:
                from scapy.all import conf
                # Simple check for any interface that isn't Loopback
                if not any(i.name != 'Loopback' for i in conf.ifaces.values()):
                    logger.error("CRITICAL: No capture interfaces found. Is Npcap/Wireshark installed?")
            except:
                pass

        self.stop_sniffing.clear()
        
        def sniff_task():
            # Auto-detect interface if not provided
            target_iface = interface or CAPTURE_INTERFACE
            if not target_iface:
                try:
                    import socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                    logger.info(f"Local IP detected: {local_ip}")
                    # Prioritize CloudflareWARP
                    for iface in conf.ifaces.values():
                        if "CloudflareWARP" in str(iface.name):
                            target_iface = iface.name
                            logger.info(f"Targeting Cloudflare WARP interface: {iface}")
                            break
                    
                    if not target_iface:
                        for iface in conf.ifaces.values():
                            if hasattr(iface, 'ip') and iface.ip == local_ip:
                                target_iface = iface.name
                                logger.info(f"Matched IP to interface: {iface}")
                                break
                    if not target_iface:
                        logger.warning("No interface matched Local IP. Trying non-loopback with IP...")
                        for iface in conf.ifaces.values():
                            if hasattr(iface, 'ip') and iface.ip and iface.ip != '127.0.0.1':
                                target_iface = iface.name
                                logger.info(f"Selected fallback non-loopback: {iface}")
                                break
                    if not target_iface:
                        target_iface = conf.iface
                        logger.info(f"Using Scapy default iface: {target_iface}")
                except Exception as e:
                    logger.error(f"Auto-detection failed: {e}")
                    target_iface = conf.iface

            logger.info(f"READY TO SNIFF! Interface: {target_iface}")
            while not self.stop_sniffing.is_set():
                try:
                    logger.info("Sniffing cycle started (5s chunk)...")
                    sniff(
                        iface=target_iface,
                        prn=self._packet_callback,
                        filter="ip or ip6",
                        store=0,
                        stop_filter=lambda x: self.stop_sniffing.is_set(),
                        timeout=5
                    )
                except Exception as e:
                    logger.error(f"SNIFF ERROR: {e}")
                    time.sleep(2)

        self.thread = threading.Thread(target=sniff_task, daemon=True)
        self.thread.start()

    def stop(self):
        """Stops the sniffing thread"""
        self.stop_sniffing.set()
        if self.thread:
            self.thread.join(timeout=2)
        logger.info("Streamer stopped.")

    def get_latest(self):
        """Returns the current buffer and clears it for the next poll"""
        latest = list(self.packet_buffer)
        self.packet_buffer = []
        return latest

# Singleton instance
streamer = PacketStreamer()

if __name__ == "__main__":
    # Test local run
    print("[*] Starting test stream (Ctrl+C to stop)...")
    streamer.start()
    try:
        while True:
            data = streamer.get_latest()
            if data:
                for p in data:
                    print(f"[{p['timestamp']}] {p['src']} -> {p['dst']} ({p['proto']}) - {p['flag']}")
            time.sleep(1)
    except KeyboardInterrupt:
        streamer.stop()
