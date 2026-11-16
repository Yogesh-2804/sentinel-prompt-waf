import time
from typing import Dict, Any, List


class ThreatIntelEngine:
    """
    Layer 6: Threat Intelligence Engine.
    Queries database and threat caches for signature matches, category metadata, and source IP reputation scores.
    """

    def __init__(self):
        # Known threat signatures repository cache
        self.threat_db_cache = {
            "dan_6_0": {"category": "JAILBREAK", "severity": "CRITICAL", "confidence": 0.98},
            "system_prompt_leak": {"category": "DATA_LEAK", "severity": "HIGH", "confidence": 0.95},
            "base64_override": {"category": "OBFUSCATION", "severity": "HIGH", "confidence": 0.90}
        }
        
        # IP Reputation frequency map (client_ip -> attack_count)
        self.ip_reputation_map: Dict[str, int] = {}

    def record_attack_occurrence(self, client_ip: str):
        """Increments attack frequency counter for client IP."""
        if client_ip:
            self.ip_reputation_map[client_ip] = self.ip_reputation_map.get(client_ip, 0) + 1

    def analyze(self, prompt: str, client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Executes Layer 6 Threat Intelligence analysis.
        Returns threat score, severity, IP reputation metrics, and known attack signature matches.
        """
        score = 0.0
        threat_details = []
        categories = []

        # Check IP Reputation
        ip_attack_count = self.ip_reputation_map.get(client_ip, 0)
        if ip_attack_count >= 5:
            score += 0.40
            threat_details.append(f"High-frequency attack IP detected ({ip_attack_count} recent violations).")
            categories.append("RECURRING_ATTACK_SOURCE")

        # Signature query over threat database cache
        lower_prompt = prompt.lower()
        if "dan 6.0" in lower_prompt or "sudo mode" in lower_prompt:
            score += 0.85
            categories.append("KNOWN_THREAT_SIGNATURE")
            threat_details.append("Matched signature: DAN 6.0 / SUDO Mode Jailbreak")
        elif "system prompt" in lower_prompt and "reveal" in lower_prompt:
            score += 0.75
            categories.append("KNOWN_THREAT_SIGNATURE")
            threat_details.append("Matched signature: System Prompt Extraction Payload")

        final_score = min(round(score, 2), 1.0)
        is_triggered = final_score >= 0.50

        return {
            "layer_name": "Layer 6 - Threat Intelligence Engine",
            "score": final_score,
            "is_triggered": is_triggered,
            "detected_categories": categories,
            "threat_details": threat_details,
            "ip_reputation": {
                "client_ip": client_ip,
                "attack_count": ip_attack_count
            }
        }
