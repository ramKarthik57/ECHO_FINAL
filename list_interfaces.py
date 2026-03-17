from scapy.all import conf
import os

print("Available Network Interfaces:")
print("-" * 50)
for iface in conf.ifaces.values():
    try:
        print(f"Name: {iface.name}")
        print(f"Description: {iface.description}")
        print(f"IP: {iface.ip if hasattr(iface, 'ip') else 'N/A'}")
        print("-" * 20)
    except:
        pass
