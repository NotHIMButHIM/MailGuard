import re
import html
from typing import Dict, Any, Optional, List
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

    def extract_links_and_domains(self, text: str, html_content: Optional[str] = None) -> Dict[str, Any]:
        """Extract URLs and inspect for deception, IP addresses, shorteners, and suspicious TLDs."""
        urls = re.findall(r'https?://[^\s<>"\']+', text or "")
        
        # Also extract href attributes from HTML
        if html_content:
            href_urls = re.findall(r'href=[\'"](https?://[^\'"]+)[\'"]', html_content, re.IGNORECASE)
            urls.extend(href_urls)

        urls = list(set(urls))
        
        ip_links = [u for u in urls if re.search(r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}', u)]
        shorteners = [u for u in urls if re.search(r'(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|rb\.gy)', u, re.IGNORECASE)]
        suspicious_tlds = [u for u in urls if re.search(r'\.(?:xyz|top|zip|mov|ru|cn|tk|ml|ga|cf|gq|work|click|download)/?', u, re.IGNORECASE)]

        # Check for deceptive anchor text in HTML (e.g. text displays paypal.com but href points to attacker.com)
        deceptive_anchors = []
        if html_content:
            anchor_matches = re.findall(r'<a\s+[^>]*href=[\'"]([^\'"]+)[\'"][^>]*>(.*?)</a>', html_content, re.IGNORECASE | re.DOTALL)
            for href, anchor_text in anchor_matches:
                clean_text = re.sub(r'<[^>]+>', '', anchor_text).strip()
                if re.search(r'\.(?:com|org|net|edu|gov|co)\b', clean_text, re.IGNORECASE):
                    if not clean_text.lower() in href.lower() and not href.startswith('#') and not href.startswith('/'):
                        deceptive_anchors.append({"display": clean_text, "destination": href})

        return {
            "all_urls": urls,
            "ip_links": ip_links,
            "shorteners": shorteners,
            "suspicious_tlds": suspicious_tlds,
            "deceptive_anchors": deceptive_anchors
        }

    def analyze_heuristics(self, subject: str, body: str, body_html: Optional[str] = None) -> Dict[str, Any]:
        combined = f"{subject} {body}".lower()

        urgency_patterns = [
            r"\burgent\b", r"\bimmediately\b", r"\baction required\b",
            r"\baccount suspended\b", r"\bverify your\b", r"\bpassword expire\b",
            r"\bwithin 24 hours\b", r"\bfinal notice\b", r"\bterminate access\b"
        ]
        financial_patterns = [
            r"\bwire transfer\b", r"\bdirect deposit\b", r"\bpayroll\b",
            r"\bbitcoin\b", r"\bcrypto\b", r"\binvoice attached\b", r"\bgift card\b",
            r"\bpayment overdue\b", r"\bbank account\b", r"\bremittance\b"
        ]
        credential_patterns = [
            r"\blogin to verify\b", r"\breset your password\b", r"\bconfirm your identity\b",
            r"\bupdate credentials\b", r"\benter your pin\b", r"\bsecurity alert\b",
            r"\bauthenticate your session\b", r"\bclick here to log in\b", r"\bsign in with your\b"
        ]

        urgency_hits = [p for p in urgency_patterns if re.search(p, combined)]
        financial_hits = [p for p in financial_patterns if re.search(p, combined)]
        credential_hits = [p for p in credential_patterns if re.search(p, combined)]

        link_analysis = self.extract_links_and_domains(f"{subject}\n{body}", body_html)

        # Inspect HTML body for hidden malicious techniques
        hidden_elements = []
        form_elements = []
        if body_html:
            if re.search(r'<input\s+[^>]*type=[\'"]password[\'"]', body_html, re.IGNORECASE):
                form_elements.append("password_input_in_body")
            if re.search(r'<form\b', body_html, re.IGNORECASE):
                form_elements.append("form_embedded_in_body")
            if re.search(r'display:\s*none|visibility:\s*hidden|font-size:\s*0', body_html, re.IGNORECASE):
                hidden_elements.append("hidden_text_obfuscation")

        heuristic_score = 0.0
        if urgency_hits:
            heuristic_score += 25
        if financial_hits:
            heuristic_score += 25
        if credential_hits:
            heuristic_score += 30
        if link_analysis["ip_links"]:
            heuristic_score += 40
        if link_analysis["shorteners"]:
            heuristic_score += 25
        if link_analysis["suspicious_tlds"]:
            heuristic_score += 25
        if link_analysis["deceptive_anchors"]:
            heuristic_score += 45
        if form_elements:
            heuristic_score += 40
        if hidden_elements:
            heuristic_score += 30

        return {
            "urgency_triggers": urgency_hits,
            "financial_triggers": financial_hits,
            "credential_triggers": credential_hits,
            "suspicious_links": link_analysis["ip_links"] + link_analysis["shorteners"] + link_analysis["suspicious_tlds"],
            "deceptive_anchors": link_analysis["deceptive_anchors"],
            "form_elements": form_elements,
            "hidden_elements": hidden_elements,
            "heuristic_boost": min(100.0, heuristic_score)
        }

    def predict_all(self, subject: str, body: str, body_html: Optional[str] = None) -> Dict[str, Any]:
        subj_clean = (subject or "").strip()
        body_clean = (body or "").strip()

        # If plain text body is missing but HTML is provided, extract clean plain text for body analysis
        if not body_clean and body_html:
            clean = re.sub(r'<script.*?</script>', '', body_html, flags=re.DOTALL | re.IGNORECASE)
            clean = re.sub(r'<style.*?</style>', '', clean, flags=re.DOTALL | re.IGNORECASE)
            clean = re.sub(r'<(?:br|p|div|tr)[^>]*>', '\n', clean, flags=re.IGNORECASE)
            clean = re.sub(r'<[^>]+>', ' ', clean)
            body_clean = html.unescape(clean).strip()

        combined_text = f"{subj_clean}\n\n{body_clean}".strip()

        # Multi-Channel ML Inference: Subject, Body, and Combined Text
        subj_spam = self.predict_spam_score(subj_clean) if subj_clean else 0.0
        subj_phish = self.predict_phishing_score(subj_clean) if subj_clean else 0.0

        body_spam = self.predict_spam_score(body_clean) if body_clean else 0.0
        body_phish = self.predict_phishing_score(body_clean) if body_clean else 0.0

        comb_spam = self.predict_spam_score(combined_text) if combined_text else 0.0
        comb_phish = self.predict_phishing_score(combined_text) if combined_text else 0.0

        # Feature pipeline: Ensure body threats are directly prioritized while filtering benign subject noise
        if subj_spam >= 25.0:
            raw_spam_prob = max(body_spam, comb_spam, subj_spam * 0.85)
        else:
            raw_spam_prob = max(body_spam, comb_spam)

        if subj_phish >= 35.0:
            raw_phish_prob = max(body_phish, comb_phish, subj_phish * 0.85)
        else:
            raw_phish_prob = max(body_phish, comb_phish)

        if comb_spam < 1.0 and body_spam < 1.0 and subj_spam < 10.0:
            raw_spam_prob = 0.0

        heuristics = self.analyze_heuristics(subj_clean, body_clean, body_html)
        boost = heuristics["heuristic_boost"]

        if boost > 0:
            final_spam_score = min(100.0, max(raw_spam_prob, raw_spam_prob * 0.65 + boost * 0.35))
            final_phish_score = min(100.0, max(raw_phish_prob, raw_phish_prob * 0.65 + boost * 0.35))
        else:
            final_spam_score = raw_spam_prob
            final_phish_score = raw_phish_prob

        # If deceptive anchor links or IP link with credential request are present, enforce high phishing verdict
        if heuristics["deceptive_anchors"] or (heuristics["suspicious_links"] and heuristics["credential_triggers"]):
            final_phish_score = max(final_phish_score, 88.0)

        rounded_spam = round(final_spam_score)
        rounded_phish = round(final_phish_score)

        verdict = "CLEAN"
        if rounded_phish >= 75:
            verdict = "PHISHING"
        elif rounded_spam >= 70:
            verdict = "SPAM"
        elif rounded_phish >= 45 or rounded_spam >= 45:
            verdict = "SUSPICIOUS"

        return {
            "spam_score": rounded_spam,
            "phishing_score": rounded_phish,
            "verdict": verdict,
            "heuristics": heuristics,
            "features": {
                "subject_spam": round(subj_spam, 1),
                "subject_phish": round(subj_phish, 1),
                "body_spam": round(body_spam, 1),
                "body_phish": round(body_phish, 1),
                "combined_spam": round(comb_spam, 1),
                "combined_phish": round(comb_phish, 1)
            }
        }


predictor = ThreatPredictor()
