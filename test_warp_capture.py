from scapy.all import sniff, conf
import sys

interface_name = "CloudflareWARP"

print(f"Testing capture on interface: {interface_name}")
print(f"Scapy config ifaces: {conf.ifaces}")

try:
    print("Starting sniff (timeout 5s)...")
    packets = sniff(iface=interface_name, count=5, timeout=5)
    print(f"Successfully captured {len(packets)} packets")
    for pkt in packets:
        print(pkt.summary())
except Exception as e:
    print(f"Capture failed: {e}")
    # Try to find the interface in conf.ifaces
    found = False
    for iface in conf.ifaces.values():
        if interface_name in str(iface.name) or interface_name in str(iface.description):
            print(f"Found matching interface: {iface.name} ({iface.description})")
            found = True
            try:
                print(f"Retrying capture on {iface.name}...")
                packets = sniff(iface=iface.name, count=5, timeout=5)
                print(f"Successfully captured {len(packets)} packets on retry")
                break
            except Exception as e2:
                print(f"Retry failed: {e2}")
    if not found:
        print("Could not find CloudflareWARP in Scapy's interface list")
