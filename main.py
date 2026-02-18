import os
import shutil
import subprocess
from engine.detective import Detective
from engine.judge import PrivacyJudge

def run_audit():
    print("--- PrivacyLens Audit Started ---")
    
    # 1. Setup
    target_app = os.path.join("sandbox", "target_app.exe")
    if not os.path.exists("sandbox"): os.mkdir("sandbox")
    if not os.path.exists(target_app):
        shutil.copy(r"C:\Windows\System32\notepad.exe", target_app)

    # 2. Policy & Scan
    privacy_policy = "We do not access your files. We do not use the internet."
    
    sherlock = Detective(target_app)
    findings = sherlock.investigate()
    
    honor = PrivacyJudge()
    report = honor.adjudicate(privacy_policy, findings)
    
    # 3. Save results for the UI to read
    # We use a simple global variable trick for Streamlit
    return report

if __name__ == "__main__":
    # Launch Streamlit directly
    print("[*] Launching Dashboard...")
    subprocess.run(["streamlit", "run", "ui/dashboard.py"])