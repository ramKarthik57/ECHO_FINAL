from scapy.all import conf
import json

interfaces = []
for iface in conf.ifaces.values():
    try:
        interfaces.append({
            "name": str(iface.name),
            "description": str(iface.description),
            "ip": str(iface.ip) if hasattr(iface, 'ip') else "N/A",
            "guid": str(iface.pcap_name) if hasattr(iface, 'pcap_name') else "N/A"
        })
    except:
        pass

with open("interfaces_full.json", "w") as f:
    json.dump(interfaces, f, indent=4)

print(f"Exported {len(interfaces)} interfaces to interfaces_full.json")
