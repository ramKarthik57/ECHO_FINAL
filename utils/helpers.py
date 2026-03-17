"""
Helper utility functions for ECHO forensic tool
"""
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Any, Tuple
import ipaddress


def generate_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
    """
    Generate a bidirectional flow key for grouping packets.
    Same flow regardless of direction.
    """
    # Sort IPs and ports to make bidirectional
    if src_ip < dst_ip:
        key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    elif src_ip > dst_ip:
        key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    else:
        # Same IP, sort by port
        if src_port < dst_port:
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    return key


def calculate_time_delta(ts1: float, ts2: float) -> float:
    """Calculate time difference in seconds"""
    return abs(ts2 - ts1)


def format_timestamp(timestamp: float) -> str:
    """Convert Unix timestamp to readable format"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')


def is_private_ip(ip: str) -> bool:
    """Check if IP is private/internal"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def calculate_upload_download_ratio(src_bytes: int, dst_bytes: int) -> float:
    """Calculate upload/download ratio"""
    if dst_bytes == 0:
        return float('inf') if src_bytes > 0 else 0.0
    return src_bytes / dst_bytes


def group_by_time_window(packets: List[Dict], window_size: float) -> List[List[Dict]]:
    """
    Group packets into time windows.
    Returns list of packet groups.
    """
    if not packets:
        return []
    
    sorted_packets = sorted(packets, key=lambda x: x['timestamp'])
    groups = []
    current_group = [sorted_packets[0]]
    
    for packet in sorted_packets[1:]:
        time_gap = packet['timestamp'] - current_group[-1]['timestamp']
        
        if time_gap <= window_size:
            current_group.append(packet)
        else:
            groups.append(current_group)
            current_group = [packet]
    
    if current_group:
        groups.append(current_group)
    
    return groups


def save_json(data: Any, filepath: str) -> None:
    """Save data to JSON file"""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


def load_json(filepath: str) -> Any:
    """Load data from JSON file"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def hash_string(s: str) -> str:
    """Generate MD5 hash of string"""
    return hashlib.md5(s.encode()).hexdigest()[:16]


def get_packet_direction(packet_src: str, suspect_ip: str) -> str:
    """
    Determine packet direction relative to suspect.
    Returns 'outbound' or 'inbound'
    """
    return 'outbound' if packet_src == suspect_ip else 'inbound'


def calculate_burst_stats(packets: List[Dict]) -> Dict[str, Any]:
    """Calculate statistics for a burst of packets"""
    if not packets:
        return {}
    
    timestamps = [p['timestamp'] for p in packets]
    sizes = [p['packet_size'] for p in packets]
    
    return {
        'packet_count': len(packets),
        'total_bytes': sum(sizes),
        'avg_packet_size': sum(sizes) / len(sizes),
        'duration': max(timestamps) - min(timestamps),
        'start_time': min(timestamps),
        'end_time': max(timestamps)
    }