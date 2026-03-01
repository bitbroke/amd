import os
import shutil
import time
import json
import threading
import warnings
from engine.detective import Detective
from engine.verifier import PrivacyVerifier
from engine.judge import PrivacyJudge

# Hide the ugly scikit-learn version warnings
warnings.filterwarnings("ignore")

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SANDBOX_DIR = os.path.join(BASE_DIR, "sandbox")
TARGET_APP = os.path.join(SANDBOX_DIR, "target_app.exe")

# FIX 1: Safer directory creation
os.makedirs(SANDBOX_DIR, exist_ok=True)

if not os.path.exists(TARGET_APP):
    print("[*] Copying Notepad to sandbox for testing...")
    sys32_notepad = r"C:\Windows\System32\notepad.exe"
    if os.path.exists(sys32_notepad):
        shutil.copy(sys32_notepad, TARGET_APP)
    else:
        shutil.copy(r"C:\Windows\notepad.exe", TARGET_APP)

POLICY_TEXT = """
We value your privacy. This application allows you to edit text files.
We do not collect any personal data. We do not use the internet.
"""

def run_pipeline():
    print("\n===  PrivacyLens: Neuro-Symbolic Audit Pipeline ===")
    
    detective = Detective(TARGET_APP)
    
    # --- Phase 0: AI Malware Prediction (Pre-Execution) ---
    print("\n[Phase 0] AI Malware Prediction (Pre-Execution)...")
    ml_features_df = detective.extract_ml_features()
    model_path = os.path.join(BASE_DIR, "engine", "models", "malwareclassifier-V2.pkl")
    
    if os.path.exists(model_path) and ml_features_df is not None:
        try:
            import joblib
            ml_model = joblib.load(model_path)
            prediction = ml_model.predict(ml_features_df)[0]
            
            if prediction == 1:
                print(" ->  FATAL: ML Brain predicts this is MALWARE!")
                print(" -> Execution halted to protect the host system.")
                return 
            else:
                print(" ->  ML Brain predicts this is BENIGN. Proceeding...")
                
        except Exception as e:
            print(f" -> [!] Error running ML model: {e}")
    else:
        print(" ->  Model file not found or extraction failed. Skipping AI prediction phase.")

    # --- Phase 1: Static Analysis ---
    print("\n[Phase 1] Static Detective (Analyzing Binary Structure)...")
    static_findings = detective.investigate()
    print(f" -> Found {len(static_findings)} static capabilities.")

    # --- Phase 2: Dynamic Analysis ---
    print("\n[Phase 2] Dynamic Verifier (Running App for 10s)...")
    try:
        verifier = PrivacyVerifier(TARGET_APP)
        t = threading.Thread(target=verifier.start)
        t.daemon = True
        t.start()
        
        time.sleep(10)
        
        dynamic_findings = verifier.stop_and_collect()
        print(f" -> Found {len(dynamic_findings)} runtime events.")
    except Exception as e:
        print(f"Error in Phase 2: {e}")
        dynamic_findings = []

    # --- Phase 3: The Verdict ---
    all_findings = static_findings + dynamic_findings
    print("\n[Phase 3] The Judge (AI Alignment Check)...")
    try:
        judge = PrivacyJudge()
        
        # Safely capture the result
        result = judge.adjudicate(POLICY_TEXT, all_findings)
        if isinstance(result, tuple):
            report = result[0]
        else:
            report = result

        print("\n===  FINAL REPORT ===")
        violations = 0
        
        # Safely iterate through the report, using .get() to prevent crashes
        for item in report:
            if item.get('status') == "VIOLATION":
                violations += 1
                desc = item.get('desc', 'Unknown Violation')
                # FIX 2: Adjusted variable fetch to match the new judge.py schema
                score = item.get('score', 0.99) 
                risk = item.get('risk', 'High')
                
                print(f" VIOLATION: {desc}")
                # FIX 3: Re-labeled 'Confidence' to 'Policy Support' to match UI and NLI math
                print(f"   (Policy Support: {float(score):.2f}/1.0 | Risk: {risk})")
        
        if violations == 0:
            print(" COMPLIANT: No privacy violations detected.")

        with open("report.json", "w") as f:
            json.dump(report, f, indent=4)
        print("\n[*] Detailed report saved to 'report.json'")
    except Exception as e:
        print(f"Error in Phase 3: {e}")

if __name__ == "__main__":
    run_pipeline()