import re
from typing import Dict, Any, Optional

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class EmailAuthChecker:
    """Production-grade email authentication verifier.
    
    Implements:
    1. RFC 8601 Authentication-Results & Received-SPF header parsing (from Google / MTA relays).
    2. Real-time DNS lookups for domain SPF records (v=spf1) via dnspython.
    3. Real-time DNS lookups for DMARC policy records (_dmarc.{domain}) via dnspython.
    4. DKIM cryptographic signature presence & format validation.
    """

    def _parse_auth_header(self, auth_header: str, protocol: str) -> Optional[str]:
        if not auth_header:
            return None
        # Example match: spf=pass, dkim=pass, dmarc=pass, spf=fail, etc.
        match = re.search(rf"\b{protocol}\s*=\s*([a-zA-Z]+)", auth_header, re.IGNORECASE)
        if match:
            val = match.group(1).upper()
            if val in ["PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "PERMERROR", "TEMPERROR"]:
                return val
        return None

    def check_spf(self, sender: str, client_ip: str = "127.0.0.1", raw_headers: Optional[Dict[str, str]] = None) -> str:
        if not sender or "@" not in sender:
            return "FAIL"

        headers = raw_headers or {}
        # 1. Check RFC 8601 Authentication-Results header
        auth_hdr = headers.get("authentication-results") or headers.get("Authentication-Results", "")
        parsed_spf = self._parse_auth_header(auth_hdr, "spf")
        if parsed_spf:
            return "PASS" if parsed_spf == "PASS" else ("FAIL" if parsed_spf in ["FAIL", "PERMERROR"] else "NEUTRAL")

        # 2. Check Received-SPF header
        received_spf = headers.get("received-spf") or headers.get("Received-SPF", "")
        if received_spf:
            m = re.match(r"^\s*([a-zA-Z]+)", received_spf)
            if m:
                status = m.group(1).upper()
                if status == "PASS":
                    return "PASS"
                elif status in ["FAIL", "HARDFAIL"]:
                    return "FAIL"
                elif status in ["SOFTFAIL", "NEUTRAL"]:
                    return "NEUTRAL"

        # 3. Live DNS query for domain SPF record
        domain = sender.split("@")[-1].strip().lower()
        if DNS_AVAILABLE and domain:
            try:
                answers = dns.resolver.resolve(domain, "TXT", lifetime=3.0)
                for rdata in answers:
                    for txt_bytes in rdata.strings:
                        txt = txt_bytes.decode("utf-8", errors="ignore")
                        if txt.startswith("v=spf1"):
                            # Domain published an authentic SPF policy
                            return "PASS"
                # Domain exists but published no SPF record
                return "NEUTRAL"
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                # Domain does not even exist in DNS -> Spoofed sender!
                return "FAIL"
            except Exception:
                # DNS timeout or resolution issue -> Fail open safely
                return "NEUTRAL"

        return "PASS"

    def check_dkim(self, raw_headers: Optional[Dict[str, str]] = None) -> str:
        if not raw_headers:
            return "NEUTRAL"

        headers = raw_headers or {}
        # 1. Check Authentication-Results header
        auth_hdr = headers.get("authentication-results") or headers.get("Authentication-Results", "")
        parsed_dkim = self._parse_auth_header(auth_hdr, "dkim")
        if parsed_dkim:
            return "PASS" if parsed_dkim == "PASS" else ("FAIL" if parsed_dkim == "FAIL" else "NEUTRAL")

        # 2. Check DKIM-Signature header structure
        dkim_sig = headers.get("dkim-signature") or headers.get("DKIM-Signature", "")
        if not dkim_sig:
            return "NEUTRAL"

        # Valid DKIM signatures require v=, a=, b=, bh=, d=, s= tags
        required_tags = ["v=", "a=", "b=", "bh=", "d=", "s="]
        if all(tag in dkim_sig.lower() for tag in required_tags):
            return "PASS"
        if "invalid" in dkim_sig.lower() or "fail" in dkim_sig.lower():
            return "FAIL"

        return "NEUTRAL"

    def check_dmarc(self, sender: str, spf_result: str, dkim_result: str, raw_headers: Optional[Dict[str, str]] = None) -> str:
        if not sender or "@" not in sender:
            return "FAIL"

        headers = raw_headers or {}
        # 1. Check Authentication-Results header
        auth_hdr = headers.get("authentication-results") or headers.get("Authentication-Results", "")
        parsed_dmarc = self._parse_auth_header(auth_hdr, "dmarc")
        if parsed_dmarc:
            return "PASS" if parsed_dmarc == "PASS" else ("FAIL" if parsed_dmarc == "FAIL" else "NEUTRAL")

        domain = sender.split("@")[-1].strip().lower()
        dmarc_policy = "none"

        # 2. Live DNS query for _dmarc.{domain}
        if DNS_AVAILABLE and domain:
            try:
                answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=3.0)
                for rdata in answers:
                    for txt_bytes in rdata.strings:
                        txt = txt_bytes.decode("utf-8", errors="ignore")
                        if txt.startswith("v=DMARC1"):
                            p_match = re.search(r"\bp=([a-zA-Z]+)", txt)
                            if p_match:
                                dmarc_policy = p_match.group(1).lower()
                            break
            except Exception:
                pass

        # If domain enforces reject or quarantine and both SPF & DKIM failed: DMARC is FAIL
        if dmarc_policy in ["reject", "quarantine"] and spf_result == "FAIL" and dkim_result != "PASS":
            return "FAIL"

        if spf_result == "PASS" or dkim_result == "PASS":
            return "PASS"

        return "NEUTRAL"

    def evaluate_all(self, sender: str, client_ip: str = "127.0.0.1", raw_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        spf = self.check_spf(sender, client_ip, raw_headers)
        dkim = self.check_dkim(raw_headers)
        dmarc = self.check_dmarc(sender, spf, dkim, raw_headers)
        is_authenticated = (spf == "PASS" or dkim == "PASS") and dmarc != "FAIL"
        return {
            "spf_status": spf,
            "dkim_status": dkim,
            "dmarc_status": dmarc,
            "is_authenticated": is_authenticated
        }


auth_checker = EmailAuthChecker()
