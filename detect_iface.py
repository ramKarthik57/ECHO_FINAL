from scapy.all import conf, get_if_list, sniff
import socket

def get_active_iface():
    # Try to find the interface that handles default gateway traffic
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        for iface in conf.ifaces.values():
            if hasattr(iface, 'ip') and iface.ip == local_ip:
                return iface.name
    except:
        pass
    return conf.iface

print(f"ACTIVE_IFACE:{get_active_iface()}")
print(f"ALL_IFACES:{get_if_list()}")
