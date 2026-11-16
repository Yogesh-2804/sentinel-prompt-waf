import time
from typing import List, Dict, Any, Optional
from app.services.semantic_detector import SemanticDetector
from app.core.logger import logger


class SelfLearningManager:
    """
    Continuous Adaptive Threat Learning Manager.
    Manages threat candidate creation, normalization/sanitization, MiniLM vector embedding generation,
    analyst approval, and automated threat persistence across restarts.
    """

    def __init__(self, semantic_detector: Optional[SemanticDetector] = None):
        self.semantic_detector = semantic_detector or SemanticDetector()

    def auto_learn_threat(
        self,
        prompt: str,
        category: str = "AUTO_LEARNED_THREAT",
        attack_family: str = "adaptive_threat_memory",
        confidence: float = 0.90,
        detector_sources: List[str] = None
    ) -> Dict[str, Any]:
        """
        Automated Adaptive Learning Pipeline:
        1. Takes high-confidence malicious prompt.
        2. Normalizes & sanitizes PII.
        3. Computes MiniLM 384-dim vector embedding.
        4. Ingests confirmed threat vector into FAISS index.
        5. Persists FAISS index and threat metadata to disk.
        """
        # Prevent threat memory poisoning by requiring high confidence
        if confidence < 0.75:
            logger.warning(f"Confidence score {confidence} too low for adaptive threat learning. Skipping.")
            return {"status": "SKIPPED_LOW_CONFIDENCE"}

        res = self.semantic_detector.add_threat_vector(
            prompt=prompt,
            category=category,
            attack_family=attack_family,
            confidence=confidence,
            status="CONFIRMED",
            detector_sources=detector_sources
        )
        logger.info(f"Auto-learned and vectorized threat into FAISS index: '{prompt[:40]}...'")
        return {
            "status": "LEARNED_AND_PERSISTED",
            "threat_id": res.get("threat_id"),
            "prompt_sanitized": res.get("sanitized_text"),
            "faiss_vector_count": res.get("total_confirmed_vectors")
        }

    def confirm_analyst_threat(
        self,
        prompt: str,
        category: str = "ANALYST_CONFIRMED_THREAT"
    ) -> Dict[str, Any]:
        """Analyst approval workflow: ingests confirmed threat into persistent FAISS index."""
        res = self.semantic_detector.add_threat_vector(
            prompt=prompt,
            category=category,
            attack_family="analyst_feedback_memory",
            status="CONFIRMED"
        )
        logger.info(f"Analyst confirmed and vectorized threat: '{prompt[:40]}...' into FAISS index")
        return {
            "status": "APPROVED_AND_VECTORIZED",
            "prompt_sanitized": res["sanitized_text"],
            "faiss_vector_count": res["total_confirmed_vectors"],
            "threat_id": res["threat_id"]
        }
