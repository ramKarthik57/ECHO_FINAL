import os
import subprocess
import shutil
import platform
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def find_wireshark():
    """
    Search for Wireshark executable on Windows.
    Returns the path to Wireshark if found, else None.
    """
    if platform.system() != "Windows":
        logger.warning("find_wireshark is currently optimized for Windows only.")
        return shutil.which("wireshark")

    # Common installation paths on Windows
    common_paths = [
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
    ]

    # Check common paths
    for path in common_paths:
        if os.path.exists(path):
            return path

    # Check PATH
    wireshark_path = shutil.which("wireshark")
    if wireshark_path:
        return wireshark_path

    return None

def open_wireshark(pcap_path):
    """
    Launch Wireshark and open the specified PCAP file.
    
    Args:
        pcap_path: Absolute path to the PCAP file.
    
    Returns:
        bool: True if launched successfully, else False.
    """
    if not os.path.exists(pcap_path):
        logger.error(f"PCAP file not found: {pcap_path}")
        return False

    wireshark_exe = find_wireshark()
    if not wireshark_exe:
        logger.error("Wireshark executable not found. Please ensure it is installed.")
        return False

    try:
        logger.info(f"Launching Wireshark: {wireshark_exe} {pcap_path}")
        # Use Popen to launch it asynchronously (non-blocking)
        subprocess.Popen([wireshark_exe, pcap_path], shell=False)
        return True
    except Exception as e:
        logger.error(f"Failed to launch Wireshark: {e}")
        return False

if __name__ == "__main__":
    # Test script
    test_pcap = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "captured_packets.pcap")
    if open_wireshark(test_pcap):
        print("Successfully launched Wireshark.")
    else:
        print("Failed to launch Wireshark.")
