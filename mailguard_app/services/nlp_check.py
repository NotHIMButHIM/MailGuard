import re
from typing import Dict, Any


class NLPThreatEngine:
    def __init__(self):
        self.threat_keywords = {
            "urgency": [
                r"\bact now\b", r"\burgent action\b", r"\bwithin 24 hours\b",
                r"\bimmediate attention\b", r"\baccount suspension\b", r"\bfinal notice\b"
            ],
            "financial_extortion": [
                r"\bwire transfer\b", r"\bbitcoin payment\b", r"\bgift cards\b",
                r"\bcrypto wallet\b", r"\bransom\b", r"\bunauthorized charge\b", r"\bpayroll update\b"
            ],
            "credential_harvesting": [
                r"\blogin to verify\b", r"\breset your password\b", r"\bconfirm your identity\b",
                r"\bupdate credentials\b", r"\benter your pin\b", r"\bssn verification\b"
            ],
            "impersonation": [
                r"\bceo\b", r"\bhelpdesk support\b", r"\bit security team\b",
                r"\bhuman resources department\b", r"\boffice 365 admin\b"
            ]
        }

    def analyze(self, subject: str, body: str) -> Dict[str, Any]:
        combined_text = f"{subject} {body}".lower()
        matched_categories = {}
        total_hits = 0

        for category, patterns in self.threat_keywords.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, combined_text)
                if found:
                    matches.extend(found)
            if matches:
                matched_categories[category] = matches
                total_hits += len(matches)

        nlp_score = min(100.0, round(total_hits * 20, 1))
        verdict = "HIGH" if nlp_score >= 70 else "MEDIUM" if nlp_score >= 40 else "LOW"

        return {
            "nlp_score": nlp_score,
            "threat_level": verdict,
            "total_hits": total_hits,
            "categories": matched_categories
        }


nlp_engine = NLPThreatEngine()
