from engine.lawyer import PrivacyLawyer

class PrivacyJudge:
    def __init__(self):
        self.lawyer = PrivacyLawyer()
        
        # FIX 1: Reordered the mapper. 
        # Specific DYNAMIC events must be evaluated before generic static events.
        self.mapper = {
            "DYNAMIC_FILE": "This application opened the file: {value} during runtime.",
            "DYNAMIC_NET": "This application established a network connection to: {value}.",
            "socket": "This application connects to the internet.",
            "send": "This application transmits data to servers.",
            "STR_URL": "This application contains a hardcoded URL: {value}.",
            "STR_IPv4": "This application connects to a specific IP address: {value}.",
            "file": "This application reads or writes to local files.",
            "reg": "This application accesses system registry keys."
        }
        
        # Risk Weights (C_i in your formula)
        self.weights = {
            "DYNAMIC_FILE": 1.0,
            "DYNAMIC_NET": 1.0,
            "socket": 0.8,
            "STR_URL": 0.6,
            "STR_IPv4": 0.7,
            "reg": 0.3,
            "send": 0.8,
            "file": 0.5 
        }
        
    def adjudicate(self, policy_text, detected_apis):
        report = []
        total_drift = 0.0
        unique_apis = list(set(detected_apis))
        
        for api in unique_apis:
            hypothesis = "This application performs background operations."
            risk_weight = 0.5 
            matched_key = None
            
            # Map technical finding to natural language
            for key, desc in self.mapper.items():
                if key.lower() in api.lower():
                    matched_key = key
                    risk_weight = self.weights.get(key, 0.5)
                    
                    if "{value}" in desc:
                        try:
                            actual_value = api.split(key + "_", 1)[-1]
                            hypothesis = desc.replace("{value}", actual_value)
                        except:
                            hypothesis = desc
                    else:
                        hypothesis = desc
                    break
            
            if not matched_key:
                continue 

            # Policy Support Score (P_i in your formula)
            policy_score = self.lawyer.review(policy_text, hypothesis)
            
            # Calculate Drift: ReLU(C_i - P_i) * W_i
            # If policy score is high (allowed), drift is 0. 
            drift_value = max(0, risk_weight - policy_score) * risk_weight
            total_drift += drift_value

            status = "VIOLATION" if drift_value > 0.3 else "COMPLIANT"
            
            # FIX 2: Changed 'policy_score' to 'score' to match the Streamlit dashboard
            report.append({
                "finding": api, 
                "desc": hypothesis, 
                "score": float(policy_score), 
                "risk": risk_weight,
                "drift": float(drift_value),
                "status": status
            })
            
        return report, total_drift