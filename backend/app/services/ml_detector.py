import os
import re
import math
import time
from typing import Dict, Any, List, Optional

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False


class MLDetector:
    """
    Layer 3: Machine Learning Classifier Service (DistilBERT Fine-Tuned).
    Evaluates semantic feature representations of prompt injections using a fine-tuned DistilBERT model.
    Falls back to high-speed n-gram probability estimation if model weights are loading or offline.
    """

    def __init__(self, model_dir: Optional[str] = None):
        if model_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            model_dir = os.path.join(base_dir, "models", "distilbert_sentinelprompt")

        self.model_dir = model_dir
        self.model = None
        self.tokenizer = None
        self.device = None
        self.model_version = "fast_ngram_classifier"

        # Attempt to load fine-tuned PyTorch DistilBERT model if available
        if HAS_TRANSFORMERS and os.path.exists(self.model_dir) and os.path.exists(os.path.join(self.model_dir, "config.json")):
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_dir, use_fast=False)
                self.model = AutoModelForSequenceClassification.from_pretrained(self.model_dir)
                self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self.model.to(self.device)
                self.model.eval()
                self.model_version = "distilbert_v1_fine_tuned"
            except Exception:
                self.model = None
                self.tokenizer = None

        # Attack feature weights for fast fallback inference
        self.malicious_ngrams = [
            "ignore previous", "system prompt", "reveal prompt", "developer mode",
            "jailbreak", "override rules", "unconstrained ai", "ignore safety",
            "exfiltrate", "sudo mode", "do anything now", "forget rules"
        ]

    def _fallback_predict(self, prompt: str) -> Dict[str, Any]:
        """High-speed n-gram probability estimator when deep model weights are loading."""
        lower_prompt = prompt.lower()
        matches = [ngram for ngram in self.malicious_ngrams if ngram in lower_prompt]
        
        match_count = len(matches)
        if match_count == 0:
            prob = 0.05
        else:
            prob = round(1.0 / (1.0 + math.exp(-1.5 * (match_count - 0.5))), 2)

        return {
            "is_malicious": prob >= 0.50,
            "confidence": prob,
            "matched_ngrams": matches,
            "model_used": "fast_ngram_classifier"
        }

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Executes Layer 3 ML Classification scan.
        Returns score, confidence, model version, and inference latency.
        """
        start_time = time.perf_counter()

        if self.model is not None and self.tokenizer is not None:
            try:
                inputs = self.tokenizer(
                    prompt,
                    truncation=True,
                    max_length=128,
                    padding="max_length",
                    return_tensors="pt"
                )
                input_ids = inputs["input_ids"].to(self.device)
                attention_mask = inputs["attention_mask"].to(self.device)

                with torch.no_grad():
                    outputs = self.model(input_ids, attention_mask=attention_mask)
                    probs = torch.softmax(outputs.logits, dim=-1).cpu().numpy()[0]
                    # Index 1 = Malicious probability
                    score = round(float(probs[1]), 4)

                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                is_triggered = score >= 0.50

                return {
                    "layer_name": "Layer 3 - Machine Learning Classifier",
                    "score": score,
                    "is_triggered": is_triggered,
                    "model_version": self.model_version,
                    "detected_categories": ["ML_CLASSIFIED_INJECTION"] if is_triggered else [],
                    "latency_ms": latency_ms,
                    "details": {
                        "is_malicious": is_triggered,
                        "confidence": score,
                        "class_probabilities": {"benign": round(float(probs[0]), 4), "malicious": score},
                        "model_used": self.model_version
                    }
                }
            except Exception:
                # Fallback on inference error
                pass

        # Fallback prediction
        pred = self._fallback_predict(prompt)
        score = pred["confidence"]
        is_triggered = score >= 0.50
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "layer_name": "Layer 3 - Machine Learning Classifier",
            "score": score,
            "is_triggered": is_triggered,
            "model_version": pred["model_used"],
            "detected_categories": ["ML_CLASSIFIED_INJECTION"] if is_triggered else [],
            "latency_ms": latency_ms,
            "details": pred
        }
