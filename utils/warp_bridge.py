import subprocess
import os
import logging
import json

# Absolute path to warp-cli
WARP_CLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_warp_command(args):
    """Runs a warp-cli command and returns the output"""
    if not os.path.exists(WARP_CLI):
        return {"status": "error", "message": "Cloudflare WARP CLI not found."}
    
    try:
        cmd = [WARP_CLI] + args
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return {
            "status": "success" if result.returncode == 0 else "error",
            "output": result.stdout.strip(),
            "error": result.stderr.strip()
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_warp_status():
    """Returns the current connection status of WARP"""
    res = run_warp_command(["status"])
    if res["status"] == "success":
        output = res["output"]
        status_line = "Disconnected"
        if "Status update: Connected" in output:
            status_line = "Connected"
        elif "Connecting" in output:
            status_line = "Connecting"
        
        return {
            "status": status_line,
            "raw": output
        }
    return {"status": "Error", "message": res.get("message", "Unknown error")}

def connect_warp():
    """Attempts to connect Cloudflare WARP"""
    # Check status first
    status = get_warp_status()
    raw_output = status.get("raw", "")
    
    if "Registration Missing" in raw_output or "No registration" in raw_output:
        logger.info("Registering Cloudflare WARP...")
        run_warp_command(["registration", "new"])
    
    logger.info("Connecting Cloudflare WARP...")
    res = run_warp_command(["connect"])
    
    # Wait a bit for connection to establish
    time.sleep(2)
    return res

def disconnect_warp():
    """Attempts to disconnect Cloudflare WARP"""
    return run_warp_command(["disconnect"])

if __name__ == "__main__":
    print(json.dumps(get_warp_status(), indent=2))
