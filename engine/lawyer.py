import os
# Fix for OpenMP Error
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Lawyer")

class PrivacyLawyer:
    def __init__(self):
        self.model_name = "cross-encoder/nli-distilroberta-base"
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        
        logger.info(f"Loading AI Model: {self.model_name}...")
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
        self.model.to(self.device)

    def review(self, policy_text, hypothesis):
        inputs = self.tokenizer(
            hypothesis, policy_text, return_tensors="pt", truncation=True, max_length=512
        ).to(self.device)

        with torch.no_grad():
            outputs = self.model(**inputs)
        
        scores = torch.nn.functional.softmax(outputs.logits, dim=1)
        
        # Index 0 = Contradiction
        # Index 1 = Neutral
        # Index 2 = Entailment
        
        contradiction = scores[0][0].item()
        entailment = scores[0][2].item()
        
        return entailment - contradiction

if __name__ == "__main__":
    print("\n--- STARTING LAWYER TEST ---")
    lawyer = PrivacyLawyer()
    test_policy = "We collect your precise location data to enable map features."
    test_hypothesis = "This application tracks the user's physical location."
    
    score = lawyer.review(test_policy, test_hypothesis)
    print(f"\nNet Admission Score: {score:.4f}")
    
    if score > 0.5:
        print("✅ VERDICT: ADMITS (Correct)")
    else:
        print("❌ VERDICT: DENIES (Wrong)")