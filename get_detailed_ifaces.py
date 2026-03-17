from scapy.all import conf
import json

ifaces = []
for iface in conf.ifaces.values():
    ifaces.append({
        "name": str(iface.name),
        "description": str(iface.description),
        "ip": str(iface.ip) if hasattr(iface, 'ip') else "N/A",
        "guid": str(iface.guid) if hasattr(iface, 'guid') else "N/A",
        "pcap_name": str(iface.pcap_name) if hasattr(iface, 'pcap_name') else "N/A",
        "index": str(iface.index) if hasattr(iface, 'index') else "N/A"
    })

print(json.dumps(ifaces, indent=2))
with open("ifaces_detailed.json", "w") as f:
    json.dump(ifaces, f, indent=2)
