import re
from typing import Dict, Any
from mailguard_app.ml.model_registry import get_model_registry


class ThreatPredictor:
    def __init__(self):
        self.registry = get_model_registry()

    def predict_spam_score(self, text: str) -> float:
        if not text or not text.strip():
            return 0.0
        try:
            probs = self.registry.spam_model.predict_proba([text])
            return float(probs[0][1]) * 100
        except Exception:
            return 0.0

    def predict_phishing_score(self, text: str) -> float:
        if not text or not text.strip():
            return 0.0
        try:
            probs = self.registry.phishing_model.predict_proba([text])
            return float(probs[0][1]) * 100
        except Exception:
            return 0.0

    def analyze_heuristics(self, subject: str, body: str) -> Dict[str, Any]:
        combined = f"{subject} {body}".lower()

        urgency_patterns = [
            r"\burgent\b", r"\bimmediately\b", r"\baction required\b",
            r"\baccount suspended\b", r"\bverify your\b", r"\bpassword expire\b"
        ]
        financial_patterns = [
            r"\bwire transfer\b", r"\bdirect deposit\b", r"\bpayroll\b",
            r"\bbitcoin\b", r"\bcrypto\b", r"\binvoice attached\b", r"\bgift card\b"
        ]
        link_patterns = [
            r"http[s]?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
            r"bit\.ly|tinyurl\.com|goo\.gl|t\.co"
        ]

        urgency_hits = [p for p in urgency_patterns if re.search(p, combined)]
        financial_hits = [p for p in financial_patterns if re.search(p, combined)]
        link_hits = [p for p in link_patterns if re.search(p, combined)]

        heuristic_score = 0.0
        if urgency_hits:
            heuristic_score += 25
        if financial_hits:
            heuristic_score += 25
        if link_hits:
            heuristic_score += 35

        return {
            "urgency_triggers": urgency_hits,
            "financial_triggers": financial_hits,
            "suspicious_links": link_hits,
            "heuristic_boost": min(100.0, heuristic_score)
        }

    def predict_all(self, subject: str, body: str) -> Dict[str, Any]:
        full_text = f"{subject}\n{body}"
        raw_spam_prob = self.predict_spam_score(full_text)
        raw_phish_prob = self.predict_phishing_score(full_text)
        heuristics = self.analyze_heuristics(subject, body)

        final_spam_score = min(100.0, raw_spam_prob * 0.7 + heuristics["heuristic_boost"] * 0.3)
        final_phish_score = min(100.0, raw_phish_prob * 0.7 + heuristics["heuristic_boost"] * 0.3)

        verdict = "CLEAN"
        if final_phish_score >= 75:
            verdict = "PHISHING"
        elif final_spam_score >= 70:
            verdict = "SPAM"
        elif final_phish_score >= 45 or final_spam_score >= 45:
            verdict = "SUSPICIOUS"

        return {
            "spam_score": round(final_spam_score),
            "phishing_score": round(final_phish_score),
            "verdict": verdict,
            "heuristics": heuristics
        }


predictor = ThreatPredictor()
