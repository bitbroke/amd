import os
import logging

# Fix for OpenMP Error
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Lawyer")


class PrivacyLawyer:
    def __init__(self, load_model=True):
        self.model = None
        self.tokenizer = None
        self.torch = None
        self.device = "cpu"

        if load_model:
            import torch
            from transformers import (
                AutoTokenizer,
                AutoModelForSequenceClassification,
            )

            self.torch = torch
            self.model_name = "cross-encoder/nli-distilroberta-base"
            self.device = "cuda" if torch.cuda.is_available() else "cpu"

            logger.info(f"Loading AI Model: {self.model_name}...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name
            )
            self.model.to(self.device)

    def review(self, policy_text, hypothesis):
        if not self.model or not self.tokenizer:
            raise RuntimeError("Model not loaded. Initialize with load_model=True.")

        inputs = self.tokenizer(
            hypothesis,
            policy_text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        ).to(self.device)

        with self.torch.no_grad():
            outputs = self.model(**inputs)

        scores = self.torch.nn.functional.softmax(outputs.logits, dim=1)

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