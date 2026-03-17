"""
Network interface helper for cross-platform support
"""
from scapy.all import get_if_list, conf
import sys
import os

def list_interfaces():
    """List all available network interfaces"""
    print("\n" + "=" * 70)
    print("Available Network Interfaces:")
    print("=" * 70)
    
    try:
        interfaces = get_if_list()
        
        for i, iface in enumerate(interfaces, 1):
            print(f"\n{i}. {iface}")
            
            # Try to get more info on Windows
            if sys.platform == 'win32':
                try:
                    # On Windows, interface names are GUIDs, let's make them readable
                    from scapy.arch.windows import get_windows_if_list
                    win_ifaces = get_windows_if_list()
                    for win_iface in win_ifaces:
                        if iface in str(win_iface.get('guid', '')):
                            desc = win_iface.get('description', 'No description')
                            print(f"   Description: {desc}")
                            ips = win_iface.get('ips', [])
                            if ips:
                                print(f"   IP: {ips}")
                            break
                except:
                    pass
        
        print("=" * 70)
        return interfaces
        
    except Exception as e:
        print(f"[!] Error listing interfaces: {e}")
        return []

def get_default_interface():
    """Get the default network interface"""
    try:
        return conf.iface
    except:
        interfaces = get_if_list()
        return interfaces[0] if interfaces else None

def select_interface():
    """Interactive interface selection"""
    interfaces = list_interfaces()
    
    if not interfaces:
        print("\n[!] No network interfaces found!")
        return None
    
    default = get_default_interface()
    print(f"\nDefault interface: {default}")
    print("=" * 70)
    
    while True:
        choice = input("\nEnter interface number (or press Enter for default): ").strip()
        
        if not choice:
            print(f"[+] Using default interface: {default}")
            return default
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                selected = interfaces[idx]
                print(f"[+] Selected interface: {selected}")
                return selected
            else:
                print("[!] Invalid choice. Try again.")
        except ValueError:
            print("[!] Please enter a number.")

if __name__ == "__main__":
    print("=" * 70)
    print("ECHO Network Interface Detector")
    print("=" * 70)
    selected = select_interface()
    if selected:
        print(f"\n[✓] Selected interface: {selected}")
        print(f"\n[*] To use this interface, update utils/config.py:")
        print(f"    CAPTURE_INTERFACE = r'{selected}'")