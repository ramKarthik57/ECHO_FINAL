try:
    from scapy.all import sniff, IP, TCP, UDP, TLS, Raw, conf
    print("Full import successful!")
except ImportError as e:
    print(f"Import failed: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
