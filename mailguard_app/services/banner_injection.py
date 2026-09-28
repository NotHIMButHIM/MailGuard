from typing import Optional, Dict, Any


class SecurityBannerInjector:
    """Injects contextual enterprise security banners directly into inbound HTML emails."""

    @staticmethod
    def _create_banner_html(title: str, message: str, bg_color: str, border_color: str, text_color: str, icon: str) -> str:
        return f"""
<!-- MAILGUARD SECURITY WARNING BANNER -->
<div style="background-color: {bg_color}; border-left: 5px solid {border_color}; color: {text_color}; padding: 12px 16px; margin: 10px 0 18px 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 13px; line-height: 1.5; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
        <span style="font-size: 16px;">{icon}</span>
        <strong style="letter-spacing: 0.5px; text-transform: uppercase;">{title}</strong>
    </div>
    <div style="font-size: 12px; opacity: 0.95;">{message}</div>
</div>
"""

    def inject_banner(
        self,
        html_body: str,
        threat_verdict: str,
        bec_hit: Optional[Dict[str, Any]] = None,
        is_external: bool = True
    ) -> str:
        if not html_body:
            return html_body

        banner_html = ""

        # Priority 1: High-Severity Executive Impersonation (BEC)
        if bec_hit:
            reason = bec_hit.get("reason", "Potential executive impersonation detected.")
            banner_html = self._create_banner_html(
                title="Critical Warning: Potential Executive Impersonation",
                message=f"{reason} <strong>Do not reply, send funds, purchase gift cards, or verify credentials.</strong>",
                bg_color="#7f1d1d",
                border_color="#ef4444",
                text_color="#fef2f2",
                icon="🚨"
            )

        # Priority 2: Suspicious or Phishing Email
        elif threat_verdict in ["PHISHING", "SPAM", "SUSPICIOUS"]:
            banner_html = self._create_banner_html(
                title="Security Alert: Elevated Threat Signals Detected",
                message="Mailguard security engines flagged this email as suspicious. Verify the sender's identity through another channel before interacting with content or attachments.",
                bg_color="#78350f",
                border_color="#f59e0b",
                text_color="#fffbeb",
                icon="⚠️"
            )

        # Priority 3: Normal External Inbound Email
        elif is_external and threat_verdict == "CLEAN":
            banner_html = self._create_banner_html(
                title="Notice: External Sender",
                message="This message originated outside your enterprise. Use caution when opening attachments or clicking external links.",
                bg_color="#1e293b",
                border_color="#38bdf8",
                text_color="#f1f5f9",
                icon="🛡️"
            )

        if not banner_html:
            return html_body

        # Insert banner at the beginning of <body> or at the very top of HTML
        if "<body" in html_body.lower():
            idx = html_body.lower().find("<body")
            end_idx = html_body.find(">", idx)
            if end_idx != -1:
                return html_body[:end_idx + 1] + banner_html + html_body[end_idx + 1:]

        return banner_html + html_body


banner_injector = SecurityBannerInjector()
