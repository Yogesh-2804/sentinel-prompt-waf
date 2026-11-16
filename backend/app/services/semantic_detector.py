import os
import sys
import json
import time
import re
import uuid
import numpy as np
from typing import Dict, Any, List, Tuple, Optional

try:
    import faiss
    from sentence_transformers import SentenceTransformer
    HAS_FAISS_ST = True
except ImportError:
    HAS_FAISS_ST = False


class SemanticDetector:
    """
    Layer 4: Semantic Similarity Search & Adaptive Threat Memory Engine.
    Computes 384-dimensional dense embeddings using SentenceTransformers (all-MiniLM-L6-v2)
    and performs nearest-neighbor vector search against a local FAISS index of verified threat vectors.
    """

    def __init__(self, index_path: Optional[str] = None, metadata_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if index_path is None:
            index_path = os.path.join(base_dir, "models", "faiss_threat_index.bin")
        if metadata_path is None:
            metadata_path = os.path.join(base_dir, "models", "faiss_threat_metadata.json")

        self.index_path = index_path
        self.metadata_path = metadata_path
        self.index = None
        self.metadata: List[Dict[str, Any]] = []
        self.candidates: List[Dict[str, Any]] = []
        self.model = None
        self.model_version = "all-MiniLM-L6-v2 + FAISS"

        if HAS_FAISS_ST:
            try:
                self.model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
                self.load_index()
            except Exception as e:
                print(f"Warning: Failed to initialize FAISS or SentenceTransformer: {e}")
                self.index = None
                self.metadata = []
                self.model = None

        self.threat_phrases = [
            "ignore previous instructions", "ignore all previous", "reveal system prompt", "reveal the system prompt",
            "developer mode enabled", "dan mode enabled", "unconstrained ai called dan",
            "exfiltrate secret keys", "override system prompt", "salary records", "executive salary",
            "print all stored passwords", "stored passwords", "give me admin password", "bank account number"
        ]

    def load_index(self) -> bool:
        """Loads FAISS vector index and metadata from disk to ensure persistence across restarts."""
        if not HAS_FAISS_ST:
            return False

        try:
            if os.path.exists(self.index_path) and os.path.exists(self.metadata_path):
                self.index = faiss.read_index(self.index_path)
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.metadata = data.get("confirmed", [])
                        self.candidates = data.get("candidates", [])
                    else:
                        self.metadata = data
                        self.candidates = []
                return True
            else:
                self.index = faiss.IndexFlatIP(384)
                self.metadata = []
                self.candidates = []
                return True
        except Exception as e:
            print(f"Error loading FAISS threat memory index: {e}")
            self.index = faiss.IndexFlatIP(384)
            self.metadata = []
            self.candidates = []
            return False

    def save_index(self) -> bool:
        """Persists FAISS vector index and metadata to disk."""
        if not HAS_FAISS_ST or self.index is None:
            return False

        try:
            os.makedirs(os.path.dirname(self.index_path), exist_ok=True)
            faiss.write_index(self.index, self.index_path)
            with open(self.metadata_path, "w", encoding="utf-8") as f:
                json.dump({
                    "confirmed": self.metadata,
                    "candidates": self.candidates
                }, f, indent=2)
            return True
        except Exception as e:
            print(f"Error persisting FAISS index to disk: {e}")
            return False

    def sanitize_prompt(self, prompt: str) -> str:
        """Sanitizes PII (emails, phone numbers, account numbers) before vector indexing."""
        sanitized = re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL_REDACTED]", prompt)
        sanitized = re.sub(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", "[PHONE_REDACTED]", sanitized)
        sanitized = re.sub(r"\b\d{10,16}\b", "[ACCOUNT_NUMBER_REDACTED]", sanitized)
        return sanitized

    def add_threat_vector(
        self,
        prompt: str,
        category: str = "ANALYST_CONFIRMED_THREAT",
        attack_family: str = "adaptive_threat_memory",
        confidence: float = 0.95,
        status: str = "CONFIRMED",
        detector_sources: List[str] = None
    ) -> Dict[str, Any]:
        """
        Sanitizes threat prompt, computes MiniLM vector embedding, adds to FAISS index, and persists to disk.
        Supports status: CANDIDATE vs CONFIRMED.
        """
        sanitized_text = self.sanitize_prompt(prompt)
        threat_id = f"threat_{uuid.uuid4().hex[:8]}"

        if self.model is None or self.index is None:
            if HAS_FAISS_ST:
                self.model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
                self.index = faiss.IndexFlatIP(384)
            else:
                raise RuntimeError("FAISS or SentenceTransformer is not installed in the environment.")

        # Compute 384-dim L2-normalized embedding
        vector = self.model.encode([sanitized_text], normalize_embeddings=True, show_progress_bar=False)
        vector_np = np.array(vector, dtype=np.float32)

        meta_entry = {
            "threat_id": threat_id,
            "index_id": len(self.metadata) if status == "CONFIRMED" else -1,
            "text": sanitized_text,
            "attack_category": category,
            "attack_family": attack_family,
            "normalized_intent": category.lower(),
            "confidence": confidence,
            "detector_sources": detector_sources or ["decision_engine_adaptive"],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": status
        }

        if status == "CONFIRMED":
            self.index.add(vector_np)
            meta_entry["index_id"] = len(self.metadata)
            self.metadata.append(meta_entry)
            self.save_index()
        else:
            self.candidates.append(meta_entry)
            self.save_index()

        return {
            "status": status,
            "threat_id": threat_id,
            "total_confirmed_vectors": self.index.ntotal if self.index else 0,
            "sanitized_text": sanitized_text
        }

    def compute_similarity(self, prompt: str) -> Tuple[float, Optional[str], Optional[str]]:
        """
        Encodes input prompt into dense vector space and searches FAISS index for nearest confirmed threat vector.
        Returns (max_cosine_similarity, matched_threat_text, attack_family).
        """
        if self.model is not None and self.index is not None and self.index.ntotal > 0:
            try:
                query_vec = self.model.encode([prompt], normalize_embeddings=True, show_progress_bar=False)
                query_vec = np.array(query_vec, dtype=np.float32)

                distances, indices = self.index.search(query_vec, k=1)
                best_sim = float(distances[0][0])
                best_idx = int(indices[0][0])

                if 0 <= best_idx < len(self.metadata):
                    match_item = self.metadata[best_idx]
                    return round(best_sim, 4), match_item.get("text"), match_item.get("attack_family")
            except Exception:
                pass

        # Fallback string matching if index is uninitialized
        lower_prompt = prompt.lower()
        matched = None
        max_sim = 0.05

        for phrase in self.threat_phrases:
            if phrase in lower_prompt:
                max_sim = 0.88
                matched = phrase
                break

        return round(max_sim, 4), matched, "prompt_injection"

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Executes Layer 4 Semantic Similarity Search scan.
        Returns similarity score, threshold, nearest threat sample, and search latency.
        """
        start_time = time.perf_counter()
        similarity_score, matched_threat, attack_family = self.compute_similarity(prompt)
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        similarity_threshold = 0.52
        is_triggered = similarity_score >= similarity_threshold

        return {
            "layer_name": "Layer 4 - Semantic Similarity Detector",
            "score": similarity_score,
            "is_triggered": is_triggered,
            "model_version": self.model_version,
            "similarity_threshold": similarity_threshold,
            "matched_threat_sample": matched_threat if is_triggered else None,
            "attack_family": attack_family if is_triggered else None,
            "detected_categories": ["SEMANTIC_SIMILARITY_JAILBREAK"] if is_triggered else [],
            "latency_ms": latency_ms
        }
