import os
import subprocess
import urllib.request
import json
from app.services.active.nmap_detector import NmapDetector

detector = NmapDetector()
bin_path = detector.resolve_binary_path()

print("=================================================================")
print("NMAP BINARY AND VERSION VERIFICATION")
print("=================================================================")
print(f"Resolved Binary Path: {bin_path}")
print(f"File Exists: {os.path.isfile(bin_path) if bin_path else False}")
print(f"Executable Permissions (os.access X_OK): {os.access(bin_path, os.X_OK) if bin_path else False}")

if bin_path:
    proc = subprocess.run([bin_path, "--version"], capture_output=True, text=True)
    print(f"Subprocess Exit Code: {proc.returncode}")
    print(f"Subprocess stdout:\n{proc.stdout.strip()}")
    if proc.stderr:
        print(f"Subprocess stderr:\n{proc.stderr.strip()}")

info = detector.check_availability()
print("\nDetector check_availability():")
for k, v in info.items():
    print(f"  {k}: {v}")

print("\n--- Live Diagnostics API check ---")
try:
    resp = urllib.request.urlopen("http://127.0.0.1:8000/api/v1/health/diagnostics")
    diag_data = json.loads(resp.read().decode())
    print("Diagnostics API nmap status:")
    print(json.dumps(diag_data.get("tools", {}).get("nmap", diag_data), indent=2))
except Exception as e:
    print(f"API Error: {e}")

