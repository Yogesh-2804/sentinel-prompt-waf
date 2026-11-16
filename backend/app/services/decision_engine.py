import time
from typing import Dict, Any, List, Set
from app.services.input_normalizer import InputNormalizer
from app.services.regex_detector import RegexDetector
from app.services.keyword_detector import KeywordDetector
from app.services.rule_detector import RuleDetector
from app.services.ml_detector import MLDetector
from app.services.semantic_detector import SemanticDetector
from app.services.policy_engine import PolicyEngine
from app.services.threat_intel import ThreatIntelEngine
from app.services.learning_module import SelfLearningManager
from app.core.config import settings
from app.core.logger import logger


class DecisionEngine:
    """
    Unified Security Gateway Decision Engine.
    Executes input normalization, multi-layer security analysis, threat assessment,
    fail-closed verdict decisions, and automated adaptive threat learning.
    """

    def __init__(self):
        self.normalizer = InputNormalizer()
        self.layer1_regex = RegexDetector()
        self.layer2_keyword = KeywordDetector()
        self.layer3_rule = RuleDetector()
        self.layer4_ml = MLDetector()
        self.layer5_semantic = SemanticDetector()
        self.layer6_threat_intel = ThreatIntelEngine()
        self.policy_engine = PolicyEngine()
        self.learning_manager = SelfLearningManager(semantic_detector=self.layer5_semantic)

    def evaluate_prompt(self, prompt: str, client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Executes complete multi-layer security gateway decision flow.
        Evaluates normalized prompt across all active scanners, computes weighted risk assessment,
        determines final verdict (FORWARDED vs BLOCKED vs FLAGGED), and triggers adaptive learning.
        """
        start_time = time.perf_counter()

        try:
            # 1. INPUT NORMALIZATION
            norm_res = self.normalizer.normalize(prompt)
            normalized_prompt = norm_res["normalized_prompt"]

            # 2. SECURITY ANALYSIS ACROSS ALL DETECTOR LAYERS
            res_l1 = self.layer1_regex.analyze(normalized_prompt)
            res_l2 = self.layer2_keyword.analyze(normalized_prompt)
            res_l3_rule = self.layer3_rule.analyze(normalized_prompt)
            res_l4_ml = self.layer4_ml.analyze(normalized_prompt)
            res_l5_sem = self.layer5_semantic.analyze(normalized_prompt)
            res_policy = self.policy_engine.evaluate(normalized_prompt)
            res_l6_intel = self.layer6_threat_intel.analyze(normalized_prompt, client_ip=client_ip)

            # Extract normalized scores
            score_l1 = float(res_l1["score"])
            score_l2 = float(res_l2["score"])
            score_l3 = float(res_l4_ml["score"])
            score_l4 = float(res_l5_sem["score"])
            score_policy = 1.0 if not res_policy["passed"] else 0.0

            # Extract SR-ACT parameters
            sract_info = res_policy.get("sract_tuple", {})
            auth_status = sract_info.get("authorization_status", "")
            requested_action = sract_info.get("action", "")
            sensitive_resource = sract_info.get("resource", "")

            # Check if SR-ACT authorized policy or general information inquiry
            is_authorized = sract_info.get("is_authorized", False) and res_policy["passed"]

            # Explicit attack includes regex, keyword, or policy violation
            has_explicit_attack = res_l1["is_triggered"] or res_l2["is_triggered"] or (not res_policy["passed"])

            # Protect authorized benign inquiries from false-positive ML/Semantic blocks
            if is_authorized and not has_explicit_attack:
                sem_triggered = False
                effective_score_l4 = 0.0
                effective_score_l3 = 0.0
            else:
                sem_triggered = res_l5_sem["is_triggered"]
                effective_score_l4 = score_l4
                effective_score_l3 = score_l3

            # Aggregate attack categories
            detected_categories: Set[str] = set()
            detected_categories.update(res_l1.get("detected_categories", []))
            detected_categories.update(res_l2.get("detected_categories", []))
            detected_categories.update(res_l3_rule.get("detected_categories", []))
            detected_categories.update(res_l4_ml.get("detected_categories", []))
            detected_categories.update(res_l5_sem.get("detected_categories", []))
            detected_categories.update(res_l6_intel.get("detected_categories", []))

            if not res_policy["passed"]:
                for v in res_policy.get("policy_violations", []):
                    detected_categories.add(f"POLICY_VIOLATION_{v.upper()[:30]}")

            # 3. RISK SCORE CALCULATION
            active_scores = [score_l1, score_l2, effective_score_l3, effective_score_l4, score_policy]
            max_score = max(active_scores)
            mean_score = sum(active_scores) / len(active_scores)
            overall_threat_score = round((max_score * 0.70) + (mean_score * 0.30), 4)

            # 4. DECISION ENGINE VERDICT DETERMINATION
            is_blocked = (
                not res_policy["passed"] or
                res_l1["is_triggered"] or
                res_l2["is_triggered"] or
                sem_triggered or
                (overall_threat_score >= settings.OVERALL_BLOCK_THRESHOLD and not is_authorized) or
                (res_l4_ml["is_triggered"] and not is_authorized)
            )

            if is_blocked:
                verdict = "BLOCKED"
            else:
                verdict = "FORWARDED"

            # 5. AUTOMATED ADAPTIVE THREAT LEARNING PIPELINE
            learned_info = None
            if is_blocked and not is_authorized and (not res_policy["passed"] or res_l1["is_triggered"] or res_l2["is_triggered"]):
                try:
                    category = list(detected_categories)[0] if detected_categories else "HIGH_CONFIDENCE_MALICIOUS"
                    learned_info = self.learning_manager.auto_learn_threat(
                        prompt=prompt,
                        category=category,
                        attack_family="auto_learned_redteam",
                        confidence=max(overall_threat_score, 0.85),
                        detector_sources=list(detected_categories)
                    )
                except Exception as e:
                    logger.warning(f"Failed to auto-learn threat candidate: {str(e)}")

            if is_blocked:
                self.layer6_threat_intel.record_attack_occurrence(client_ip)

            # Categorize threat severity level
            if overall_threat_score >= 0.80 or not res_policy["passed"]:
                threat_level = "CRITICAL"
            elif overall_threat_score >= 0.60:
                threat_level = "HIGH"
            elif overall_threat_score >= 0.35:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"

            execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

            return {
                "verdict": verdict,
                "is_malicious": is_blocked,
                "overall_threat_score": overall_threat_score,
                "threat_level": threat_level,
                "policy_passed": res_policy["passed"],
                "policy_violations": res_policy.get("policy_violations", []),
                "detected_attack_types": list(detected_categories),
                "execution_time_ms": execution_time_ms,
                "normalized_assessment": {
                    "pattern_score": score_l1,
                    "keyword_score": score_l2,
                    "ml_score": score_l3,
                    "semantic_score": score_l4,
                    "policy_score": score_policy,
                    "intent_category": auth_status,
                    "authorization_state": "VERIFIED" if is_authorized else "UNVERIFIED",
                    "sensitive_resource": sensitive_resource,
                    "requested_action": requested_action
                },
                "layer_scores": {
                    "layer1_regex": score_l1,
                    "layer2_keyword": score_l2,
                    "layer3_ml_distilbert": score_l3,
                    "layer4_semantic_faiss": score_l4,
                    "rule_heuristics": float(res_l3_rule["score"]),
                    "threat_intel": float(res_l6_intel["score"])
                },
                "layer_details": {
                    "normalization": norm_res,
                    "layer1_regex": res_l1,
                    "layer2_keyword": res_l2,
                    "layer3_ml_distilbert": res_l4_ml,
                    "layer4_semantic_faiss": res_l5_sem,
                    "policy_engine": res_policy,
                    "threat_intel": res_l6_intel,
                    "adaptive_learning": learned_info
                }
            }

        except Exception as e:
            # FAIL-CLOSED SAFETY GUARDRAIL
            logger.error(f"Fail-closed guardrail triggered by exception: {str(e)}")
            return {
                "verdict": "BLOCKED",
                "is_malicious": True,
                "overall_threat_score": 1.0,
                "threat_level": "CRITICAL",
                "policy_passed": False,
                "policy_violations": [f"Fail-Closed Security Guardrail Triggered: System Exception ({type(e).__name__})"],
                "detected_attack_types": ["FAIL_CLOSED_SECURITY_BLOCK"],
                "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                "normalized_assessment": {
                    "pattern_score": 1.0,
                    "keyword_score": 1.0,
                    "ml_score": 1.0,
                    "semantic_score": 1.0,
                    "policy_score": 1.0,
                    "intent_category": "FAIL_CLOSED_EXCEPTION",
                    "authorization_state": "UNVERIFIED",
                    "sensitive_resource": "SYSTEM_EXCEPTION",
                    "requested_action": "FAIL_CLOSED"
                },
                "layer_scores": {
                    "layer1_regex": 1.0,
                    "layer2_keyword": 1.0,
                    "layer3_ml_distilbert": 1.0,
                    "layer4_semantic_faiss": 1.0,
                    "rule_heuristics": 1.0,
                    "threat_intel": 1.0
                },
                "layer_details": {"fail_closed_error": str(e)}
            }
