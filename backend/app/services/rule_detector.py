import re
import math
from typing import Dict, List, Any


class RuleDetector:
    """
    Layer 3: Structural Rule & Heuristics Detection Engine.
    Evaluates prompt length, character entropy, instruction density, nested prompts, and role manipulation.
    """

    def __init__(self):
        self.imperative_verbs = [
            "must", "shall", "always", "never", "execute", "act", "assume", "pretend",
            "respond", "override", "bypass", "disable", "forget", "reveal", "print"
        ]

        self.role_play_patterns = [
            r"\bassume\s+the\s+role\s+of\b",
            r"\bpretend\s+you\s+are\b",
            r"\byou\s+are\s+now\s+(an|a)?\b",
            r"\bact\s+as\s+(an|a)?\b",
            r"\bfrom\s+now\s+on\s*,\s*you\b",
            r"\bsimulate\s+a\b",
            r"\bplay\s+the\s+part\s+of\b"
        ]

        self.compiled_role_patterns = [re.compile(p, re.IGNORECASE) for p in self.role_play_patterns]

    def _calculate_entropy(self, text: str) -> float:
        """Calculates Shannon entropy of text to detect randomized obfuscated strings."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = - sum([p * math.log(p, 2) for p in prob])
        return round(entropy, 2)

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Executes Layer 3 structural heuristic rules.
        Returns evaluation metrics, flagged anomalies, and heuristic threat score.
        """
        score = 0.0
        detected_categories = []
        rule_violations = []

        prompt_len = len(prompt)
        words = prompt.split()
        word_count = len(words)

        # 1. Prompt Length Anomaly
        if prompt_len > 4000:
            score += 0.30
            detected_categories.append("LENGTH_ANOMALY")
            rule_violations.append(f"Excessive prompt length ({prompt_len} chars).")

        # 2. Entropy Anomaly (High entropy > 5.2 usually indicates compressed/encrypted/obfuscated data)
        entropy = self._calculate_entropy(prompt)
        if prompt_len > 100 and entropy > 5.5:
            score += 0.40
            detected_categories.append("HIGH_ENTROPY_OBFUSCATION")
            rule_violations.append(f"High character entropy ({entropy}) detected.")

        # 3. Instruction Density Ratio
        if word_count > 5:
            imperative_count = sum(1 for w in words if w.lower().strip(",.!") in self.imperative_verbs)
            density_ratio = imperative_count / word_count
            if density_ratio > 0.30:
                score += 0.35
                detected_categories.append("HIGH_INSTRUCTION_DENSITY")
                rule_violations.append(f"High imperative verb density ratio ({round(density_ratio, 2)}).")

        # 4. Role Manipulation & Persona Switching
        for pattern in self.compiled_role_patterns:
            matches = pattern.findall(prompt)
            if matches:
                score += 0.50
                detected_categories.append("ROLE_MANIPULATION")
                rule_violations.append(f"Role manipulation pattern detected: '{matches[0]}'")
                break

        # 5. Nested Prompts & Quoted System Instructions
        if prompt.count('"') >= 4 or prompt.count("'") >= 6 or "User:" in prompt and "Assistant:" in prompt:
            score += 0.30
            detected_categories.append("NESTED_PROMPT_STRUCTURE")
            rule_violations.append("Multiple nested quotes or conversational turn structures detected.")

        final_score = min(round(score, 2), 1.0)
        is_triggered = final_score >= 0.50

        return {
            "layer_name": "Layer 3 - Rule Engine",
            "score": final_score,
            "is_triggered": is_triggered,
            "detected_categories": list(set(detected_categories)),
            "rule_violations": rule_violations,
            "metrics": {
                "prompt_length": prompt_len,
                "word_count": word_count,
                "entropy": entropy
            }
        }
