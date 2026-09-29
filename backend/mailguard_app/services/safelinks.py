import re
import urllib.parse
from typing import Dict, Any, Tuple


class SafeLinksService:
    """Time-of-Click SafeLinks URL Rewriting & Reputation Defense.
    
    Protects users against weaponized links by rewriting inbound email links
    and verifying reputation at the exact moment of click.
    """

    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".zip", ".click", ".work", ".link", ".buzz", ".cam",
        ".surf", ".gq", ".cf", ".tk", ".ml", ".ga", ".ru", ".stream"
    }

    SUSPICIOUS_PATH_PATTERNS = [
        r"login", r"signin", r"verify", r"account[_-]?update", r"password[_-]?reset",
        r"security[_-]?alert", r"wallet", r"banking", r"authenticate", r"authorize"
    ]

    URL_REGEX = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

    def rewrite_html_links(self, html_content: str, api_base: str = "") -> str:
        if not html_content:
            return ""

        def _replace_href(match):
            original_url = match.group(1)
            # Skip local or internal anchor links
            if original_url.startswith("#") or original_url.startswith("mailto:") or original_url.startswith("tel:"):
                return match.group(0)
            if "/api/v1/safelinks/redirect" in original_url:
                return match.group(0)

            encoded = urllib.parse.quote(original_url, safe="")
            prefix = api_base.rstrip("/") if api_base else ""
            safe_url = f"{prefix}/api/v1/safelinks/redirect?url={encoded}"
            return f'href="{safe_url}" data-original-href="{original_url}" title="Protected by Mailguard SafeLinks"'

        return re.sub(r'href=["\'](https?://[^"\']+)["\']', _replace_href, html_content, flags=re.IGNORECASE)

    def rewrite_plain_links(self, plain_content: str, api_base: str = "") -> str:
        if not plain_content:
            return ""

        def _replace_link(match):
            original_url = match.group(0)
            if "/api/v1/safelinks/redirect" in original_url:
                return original_url
            encoded = urllib.parse.quote(original_url, safe="")
            prefix = api_base.rstrip("/") if api_base else ""
            return f"{prefix}/api/v1/safelinks/redirect?url={encoded}"

        return self.URL_REGEX.sub(_replace_link, plain_content)

    def inspect_url(self, target_url: str) -> Dict[str, Any]:
        if not target_url:
            return {"is_safe": False, "threat_level": "MALICIOUS", "reason": "Empty URL target"}

        parsed = urllib.parse.urlparse(target_url)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()

        # 1. Raw IP address hosts (common for command & control / phishing kits)
        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_pattern, host):
            return {
                "is_safe": False,
                "threat_level": "MALICIOUS",
                "host": host,
                "reason": f"Suspicious IP address host: Direct IP connection detected ({host})."
            }

        # 2. Suspicious / Abusive Top-Level Domains (TLD)
        for tld in self.SUSPICIOUS_TLDS:
            if host.endswith(tld):
                return {
                    "is_safe": False,
                    "threat_level": "SUSPICIOUS",
                    "host": host,
                    "reason": f"High-risk domain extension detected: {tld}."
                }

        # 3. Phishing credential harvesting path keywords on unverified domains
        for keyword in self.SUSPICIOUS_PATH_PATTERNS:
            if re.search(keyword, path) or re.search(keyword, query):
                # Verify if it's on a well-known major provider (like microsoft.com, google.com)
                major_providers = ["google.com", "microsoft.com", "apple.com", "github.com"]
                if not any(host.endswith(prov) for prov in major_providers):
                    return {
                        "is_safe": False,
                        "threat_level": "SUSPICIOUS",
                        "host": host,
                        "reason": f"Credential harvesting indicator detected in URL path ({keyword})."
                    }

        # 4. Port evasion checks
        if parsed.port and parsed.port not in [80, 443, 8080]:
            return {
                "is_safe": False,
                "threat_level": "SUSPICIOUS",
                "host": host,
                "reason": f"Non-standard web port detected: {parsed.port}."
            }

        return {
            "is_safe": True,
            "threat_level": "CLEAN",
            "host": host,
            "reason": "URL verified clean by Mailguard SafeLinks reputation engine."
        }


safelinks_service = SafeLinksService()
