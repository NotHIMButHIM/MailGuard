import re
from typing import List, Dict, Any


class DLPInspector:
    def __init__(self):
        self.patterns = {
            "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
            "AADHAAR": r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",
            "SSN": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
            "CREDIT_CARD": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            "PHONE_NUMBER": r"\b(?:\+91[\-\s]?)?[789]\d{9}\b|\b\d{3}[-.\s]??\d{3}[-.\s]??\d{4}\b"
        }

    def _mask_value(self, val: str, pattern_type: str) -> str:
        clean = val.replace(" ", "").replace("-", "")
        if len(clean) <= 4:
            return "****"
        return f"{clean[:2]}{'*' * (len(clean) - 4)}{clean[-2:]}"

    def inspect_text(self, text: str) -> List[Dict[str, Any]]:
        if not text:
            return []

        incidents = []
        for p_type, regex in self.patterns.items():
            matches = re.findall(regex, text)
            if matches:
                severity = "CRITICAL" if p_type in ["PAN", "AADHAAR", "CREDIT_CARD", "SSN"] else "MEDIUM"
                sample = matches[0] if matches else ""
                incidents.append({
                    "pattern_type": p_type,
                    "matches_count": len(matches),
                    "severity": severity,
                    "masked_sample": self._mask_value(sample, p_type)
                })
        return incidents


dlp_inspector = DLPInspector()
