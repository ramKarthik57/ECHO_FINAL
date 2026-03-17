from scapy.all import conf, sniff, get_if_list
import sys

print("Python version:", sys.version)
print("Scapy version:", conf.version)

print("\n--- Available Interfaces ---")
try:
    print(conf.ifaces)
except Exception as e:
    print("Error listing interfaces:", e)

print("\n--- Test Sniff (3 seconds) ---")
try:
    def pkt_callback(pkt):
        print(f"Captured: {pkt.summary()}")
    
    sniff(count=5, timeout=3, prn=pkt_callback)
    print("Sniff test complete.")
except Exception as e:
    print("Sniff test failed:", e)
