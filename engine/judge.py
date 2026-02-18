from engine.lawyer import PrivacyLawyer

class PrivacyJudge:
    def __init__(self):
        self.lawyer = PrivacyLawyer()
        # Mapper with dynamic placeholders
        self.mapper = {
            "socket": "This application connects to the internet.",
            "send": "This application transmits data to servers.",
            "STR_URL": "This application attempts to communicate with the website: {value}.",
            "STR_IPv4": "This application attempts to connect to a raw server at: {value}.",
            "file": "This application accesses or modifies local files.",
            "reg": "This application accesses system registry settings."
        }
        
        # NEW: Risk Weights (0.0 to 1.0)
        self.weights = {
            "socket": 1.0,    # Critical Risk
            "STR_URL": 1.0,   # Critical Risk
            "STR_IPv4": 1.0,  # Critical Risk
            "reg": 0.4,       # Medium-Low Risk
            "send": 0.2,      # Low Risk (Often just UI noise)
            "file": 0.7       # High-Medium Risk
        }
        
    def adjudicate(self, policy_text, detected_apis):
        report = []
        unique_apis = list(set(detected_apis))
        
        for api in unique_apis:
            hypothesis = "This application performs background operations."
            risk_weight = 0.5 # Default risk
            
            # 1. Match the API to a Description and a Weight
            for key, desc in self.mapper.items():
                if key in api:
                    risk_weight = self.weights.get(key, 0.5)
                    # Dynamic Formatting for URLs/IPs
                    if "{value}" in desc:
                        actual_value = api.split(key + "_")[-1]
                        hypothesis = desc.replace("{value}", actual_value)
                    else:
                        hypothesis = desc
                    break
            
            # 2. AI Review
            print(f"  -> Cross-examining: {api}")
            score = self.lawyer.review(policy_text, hypothesis)
            
            # 3. PRODUCTION LOGIC: Weighted Status
            # We only flag a violation if (AI is suspicious) AND (API is High Risk)
            if score < 0.4 and risk_weight >= 0.6:
                status = "VIOLATION"
            elif score < 0.2: # Extreme suspicion flags even low-risk APIs
                status = "VIOLATION"
            else:
                status = "COMPLIANT"
            
            report.append({
                "api": api, 
                "desc": hypothesis, 
                "score": score, 
                "status": status,
                "risk": risk_weight
            })
            
        return report