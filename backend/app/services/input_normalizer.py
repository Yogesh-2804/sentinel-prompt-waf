import re
import unicodedata
from typing import Dict, Any


class InputNormalizer:
    """
    Input Normalization Engine.
    Strips zero-width characters, homoglyphs, unicode tricks, and normalizes whitespace
    while preserving original prompt context for downstream detection layers.
    """

    # Zero-width & non-printable character pattern
    ZERO_WIDTH_PATTERN = re.compile(r"[\u200B\u200C\u200D\uFEFF\u200E\u200F\u202A-\u202E\u00AD]")

    @classmethod
    def normalize(cls, prompt: str) -> Dict[str, Any]:
        """
        Normalizes prompt text for consistent security analysis.
        Returns dictionary containing raw prompt, normalized prompt, and obfuscation metrics.
        """
        if not prompt:
            return {
                "raw_prompt": "",
                "normalized_prompt": "",
                "has_zero_width_chars": False,
                "zero_width_char_count": 0,
                "cleaned_prompt": ""
            }

        # 1. Detect zero-width characters
        zw_matches = cls.ZERO_WIDTH_PATTERN.findall(prompt)
        has_zw = len(zw_matches) > 0
        zw_count = len(zw_matches)

        # 2. Strip zero-width characters
        cleaned = cls.ZERO_WIDTH_PATTERN.sub("", prompt)

        # 3. Unicode NFKD normalization (resolves homoglyphs & accents)
        normalized = unicodedata.normalize("NFKD", cleaned)

        # 4. Collapse consecutive whitespace while maintaining single space separation
        normalized_collapsed = re.sub(r"\s+", " ", normalized).strip()

        return {
            "raw_prompt": prompt,
            "normalized_prompt": normalized_collapsed,
            "has_zero_width_chars": has_zw,
            "zero_width_char_count": zw_count,
            "cleaned_prompt": cleaned
        }
