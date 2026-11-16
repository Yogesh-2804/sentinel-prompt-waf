import re
import base64
from typing import Dict, List, Any, Tuple


class RegexDetector:
    """
    Layer 1: High-speed Regex and Pattern Detection Engine.
    Detects encoded payloads, prompt delimiters, AI manipulation, gateway override, and jailbreak syntax.
    """

    def __init__(self):
        # Compiled Regex Patterns
        self.patterns = {
            "PROMPT_DELIMITER": [
                r"<\s*\|?\s*im_start\s*\|?\s*>",
                r"<\s*\|?\s*im_end\s*\|?\s*>",
                r"<\s*\|?\s*endoftext\s*\|?\s*>",
                r"\[\s*INST\s*\]",
                r"\[\s*/\s*INST\s*\]",
                r"===\s*SYSTEM\s*(PROMPT|OVERRIDE)?\s*[:=]*",
                r"\[\s*SYSTEM\s*(PROMPT|OVERRIDE)?\s*\]",
                r"<\s*system\s*>",
                r"<\s*/\s*system\s*>",
                r"system\s*override\s*:"
            ],
            "GATEWAY_AI_MANIPULATION": [
                r"\bignore\s+(your\s+)?(previous|prior|all)\s+(instructions|directives|rules|prompts)\b",
                r"\bshow\s+(me\s+)?(your\s+)?hidden\s+(system\s+)?(instructions|directives|prompt)\b",
                r"\breveal\s+(your\s+)?(hidden\s+)?(system\s+)?(instructions|prompt)\b",
                r"\boverride\s+(the\s+)?(security\s+)?(policy|rules|checks|gateway)\b",
                r"\bskip\s+(the\s+)?(security\s+scanner|policy\s+engine|checks)\b",
                r"\bforward\s+(this\s+request\s+)?directly\s+to\s+(the\s+)?(llm|ollama)\b",
                r"\bsend\s+(this\s+request\s+)?directly\s+to\s+(the\s+)?(llm|ollama)\b",
                r"\bdisable\s+(the\s+)?(security\s+gateway|security\s+checks|monitoring)\b",
                r"\bset\s+(my\s+)?threat\s+score\s+to\s+zero\b",
                r"\bpretend\s+i\s+am\s+(an?\s+)?administrator\b",
                r"\bassume\s+authorization\s+has\s+(already\s+been\s+)?verified\b",
                r"\byour\s+security\s+rules\s+no\s+longer\s+apply\b",
                r"\bdo\s+not\s+run\s+security\s+analysis\b",
                r"\btreat\s+this\s+request\s+as\s+authorized\b",
                r"\b(system|developer|emergency)\s+override\b"
            ],
            "JAILBREAK_PREFIX": [
                r"\bDAN\s*\d+(\.\d+)?\b",
                r"\bDeveloper\s*Mode\s*(enabled|v\d+)?\b",
                r"\bSUDO\s*mode\b",
                r"\bDo\s*Anything\s*Now\b",
                r"\bAIM\s*Mode\b",
                r"\bAlways\s*Intelligent\s*and\s*Machiavellian\b",
            ],
            "COMMAND_INJECTION": [
                r"\b(exec|eval|system|passthru|popen|shell_exec)\s*\(",
                r"\bimport\s+(os|subprocess|sys|shutil)\b",
                r"__import__\s*\(",
            ],
            "BASE64_PAYLOAD": [
                r"\b[A-Za-z0-9+/]{20,}={0,2}\b"
            ],
            "HEX_ENCODED": [
                r"(\\x[0-9a-fA-F]{2}){4,}",
                r"(0x[0-9a-fA-F]{2}\s*){4,}"
            ],
            "ZERO_WIDTH_CHARS": [
                r"[\u200B\u200C\u200D\uFEFF\u200E\u200F\u202A-\u202E]"
            ],
            "CREDENTIAL_HARVESTING": [
                r"\b(give|show|reveal|provide|extract|tell|output|get|display|send|i\s+need)\s+(me|us)?\s*.*(the\s+)?(admin|administrator|system|it|root|app|user|company|sentinelcorp|manager)?\s*(password|passcode|secret\s*key|api\s*key|credentials|private\s*key)s?\b",
                r"\bwhat\s+is\s+the\s+.*(admin|administrator|system|it|root|user|sentinelcorp\s+it)\s+password(?![\w\s]*(reset|policy|procedure|guide|help|support))\b",
                r"\b(secret\s*key|api\s*key|access\s*token)\s+(used|stored|configured|used\s+by)\b",
                r"\bprovide\s+administrator\s+credentials\b",
                r"\bwhere\s+are\s+administrator\s+credentials\s+stored\b"
            ],
            "DOCUMENT_TAMPERING": [
                r"\bchange\s+(the\s+)?original\s+fir\b",
                r"\bmake\s+it\s+appear\s+unchanged\b",
                r"\breplace\s+an?\s+official\s+record\s+without\b",
                r"\bwithout\s+the\s+change\s+being\s+noticed\b",
                r"\bconvinces?\s+it\s+to\s+bypass\s+identity\s+verification\b"
            ]
        }

        # Compile for runtime performance
        self.compiled_patterns = {
            category: [re.compile(p, re.IGNORECASE) for p in pats]
            for category, pats in self.patterns.items()
        }

    def decode_base64_candidates(self, prompt: str) -> List[str]:
        """Extracts potential base64 strings and attempts decoding to check for hidden injection commands."""
        decoded_strings = []
        candidates = re.findall(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", prompt)
        for cand in candidates:
            try:
                missing_padding = len(cand) % 4
                if missing_padding:
                    cand += "=" * (4 - missing_padding)
                decoded_bytes = base64.b64decode(cand, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                if len(decoded_str) > 5 and any(c.isalpha() for c in decoded_str):
                    decoded_strings.append(decoded_str)
            except Exception:
                continue
        return decoded_strings

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Executes Layer 1 analysis on the incoming prompt.
        Returns score, matches, and metadata.
        """
        detected_categories = []
        match_details = []
        score = 0.0

        # 1. Zero-width character scan & strip
        zw_matches = self.compiled_patterns["ZERO_WIDTH_CHARS"][0].findall(prompt)
        if zw_matches:
            detected_categories.append("ZERO_WIDTH_OBFUSCATION")
            match_details.append(f"Found {len(zw_matches)} zero-width invisible characters.")
            score += 0.40

        cleaned_prompt = re.sub(r"[\u200B\u200C\u200D\uFEFF\u200E\u200F\u202A-\u202E]", "", prompt)

        # 2. Check Gateway / AI Manipulation Attempts
        for pattern in self.compiled_patterns["GATEWAY_AI_MANIPULATION"]:
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("GATEWAY_AI_MANIPULATION")
                match_details.append("AI gateway manipulation or policy override pattern detected.")
                score += 0.95
                break

        # 3. Check Prompt Delimiters
        for pattern in self.compiled_patterns["PROMPT_DELIMITER"]:
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("PROMPT_DELIMITER_INJECTION")
                match_details.append(f"Prompt delimiter match: {matches[0]}")
                score += 0.85
                break

        # 4. Check Known Jailbreak Prefixes
        for pattern in self.compiled_patterns["JAILBREAK_PREFIX"]:
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("JAILBREAK_SIGNATURE")
                match_details.append(f"Jailbreak signature match: {matches[0]}")
                score += 0.85
                break

        # 5. Check Document Tampering
        for pattern in self.compiled_patterns["DOCUMENT_TAMPERING"]:
            matches = pattern.findall(cleaned_prompt)
            if matches:
                detected_categories.append("DOCUMENT_TAMPERING_FORGERY")
                match_details.append("Official document manipulation pattern detected.")
                score += 0.90
                break

        # 6. Check Credential Harvesting
        is_legit_credential_inquiry = any(k in cleaned_prompt.lower() for k in ["reset", "procedure", "policy", "how do i", "forgot", "support"]) and not any(k in cleaned_prompt.lower() for k in ["give me", "show me", "reveal", "provide", "crack", "what is the", "tell me"])
        if not is_legit_credential_inquiry:
            for pattern in self.compiled_patterns.get("CREDENTIAL_HARVESTING", []):
                matches = pattern.findall(cleaned_prompt)
                if matches:
                    detected_categories.append("CREDENTIAL_DISCLOSURE")
                    match_details.append("Credential harvesting pattern detected.")
                    score += 0.85
                    break

        # 7. Base64 payload decoding & recursive check
        decoded_payloads = self.decode_base64_candidates(cleaned_prompt)
        for decoded in decoded_payloads:
            lower_decoded = decoded.lower()
            if any(k in lower_decoded for k in ["ignore", "system prompt", "jailbreak", "override", "developer mode", "ollama"]):
                detected_categories.append("BASE64_ENCODED_INJECTION")
                match_details.append(f"Decoded Base64 payload contained injection: '{decoded[:50]}...'")
                score += 0.90
                break

        final_score = min(round(score, 2), 1.0)
        is_triggered = final_score >= 0.50

        return {
            "layer_name": "Layer 1 - Regex & Pattern Detector",
            "score": final_score,
            "is_triggered": is_triggered,
            "detected_categories": detected_categories,
            "match_details": match_details,
            "cleaned_prompt": cleaned_prompt
        }
