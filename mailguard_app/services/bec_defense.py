import re
import email.utils
from typing import Dict, Any, Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from mailguard_app.models.user import User


class BECDefenseEngine:
    """Business Email Compromise (BEC) and Executive Impersonation Defense.
    
    Protects organizations against:
    1. Display Name Spoofing: External senders using the exact display name of executives.
    2. Executive Title Spoofing: Senders claiming to be CEO, CFO, HR, IT Director.
    3. Lookalike / Typosquatting Domains: Senders using homoglyph or lookalike domains.
    """

    EXECUTIVE_KEYWORDS = [
        r"\bceo\b", r"\bcfo\b", r"\bcoo\b", r"\bcto\b", r"\bchief executive\b",
        r"\bchief financial\b", r"\bpayroll\b", r"\bhuman resources director\b",
        r"\bmanaging director\b", r"\bpresident\b", r"\bvice president\b"
    ]

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Calculate edit distance between two strings."""
        if len(s1) < len(s2):
            return BECDefenseEngine._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    PUBLIC_WEBMAIL_DOMAINS = [
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
        "protonmail.com", "proton.me", "aol.com", "mail.com", "zoho.com", "yandex.com"
    ]

    async def evaluate_impersonation(
        self,
        raw_sender: str,
        subject: str = "",
        body: str = "",
        db: Optional[AsyncSession] = None
    ) -> Optional[Dict[str, Any]]:
        raw_sender = (raw_sender or "").strip()
        display_name, actual_email = email.utils.parseaddr(raw_sender)
        display_name = display_name.strip()
        actual_email = actual_email.strip().lower()

        # If parseaddr failed because raw_sender didn't contain angle brackets
        if not actual_email and "@" in raw_sender:
            actual_email = raw_sender.lower()

        if not display_name and not actual_email:
            return None

        local_part = actual_email.split("@")[0] if "@" in actual_email else actual_email
        is_free_webmail = any(provider in actual_email for provider in self.PUBLIC_WEBMAIL_DOMAINS)

        # 1. Check if display name or local part mimics a registered company user/admin
        if db:
            stmt = select(User).where(User.is_active == True)
            users = (await db.execute(stmt)).scalars().all()

            # If sender's actual email is an active registered user with matching display name, it is legitimate
            matching_registered_sender = next((u for u in users if (u.email or "").strip().lower() == actual_email), None)
            if matching_registered_sender:
                m_name = (matching_registered_sender.full_name or "").strip().lower()
                if not display_name or display_name.lower() in m_name or m_name in display_name.lower():
                    return None

            for u in users:
                user_name = (u.full_name or "").strip().lower()
                user_email = (u.email or "").strip().lower()
                user_local = user_email.split("@")[0] if "@" in user_email else ""

                if not user_name or len(user_name) < 3:
                    continue

                # A. Display name matches real employee name, but actual email is external
                if display_name:
                    display_clean = display_name.lower()
                    if (user_name == display_clean or display_clean in user_name) and actual_email != user_email:
                        return {
                            "is_impersonation": True,
                            "type": "DISPLAY_NAME_SPOOFING",
                            "target_user": u.full_name,
                            "target_role": u.role,
                            "actual_sender": actual_email,
                            "reason": f"Executive Impersonation Detected: Display name '{display_name}' mimics {u.full_name} ({u.role}), but sent from external address '{actual_email}'."
                        }

                # B. External free webmail local part mimics real employee name (e.g. himadri.pal@gmail.com)
                if is_free_webmail and actual_email != user_email:
                    # Clean local part by removing dots/underscores
                    clean_local = re.sub(r'[\._\-0-9]', '', local_part).lower()
                    clean_user_name = re.sub(r'[\._\-0-9\s]', '', user_name).lower()
                    if (clean_user_name and clean_user_name in clean_local) or (clean_local and clean_local == clean_user_name):
                        return {
                            "is_impersonation": True,
                            "type": "DISPLAY_NAME_SPOOFING",
                            "target_user": u.full_name,
                            "target_role": u.role,
                            "actual_sender": actual_email,
                            "reason": f"Executive Impersonation Detected: Sender address '{actual_email}' mimics {u.full_name} ({u.role}) via public webmail."
                        }

        # 2. Check for executive title spoofing in display name OR email local part
        check_targets = []
        if display_name:
            check_targets.append(("Display Name", display_name))
        if local_part:
            # Replace punctuation with spaces for regex matching (e.g. ceo.desk -> ceo desk)
            normalized_local = re.sub(r'[\._\-]', ' ', local_part)
            check_targets.append(("Email Address", normalized_local))

        for target_label, target_str in check_targets:
            target_lower = target_str.lower()
            for pattern in self.EXECUTIVE_KEYWORDS:
                if re.search(pattern, target_lower):
                    if is_free_webmail:
                        return {
                            "is_impersonation": True,
                            "type": "EXECUTIVE_TITLE_SPOOFING",
                            "target_user": display_name or local_part,
                            "actual_sender": actual_email,
                            "reason": f"VIP Title Spoofing: {target_label} '{target_str.strip()}' claims executive authority but sends from free/public webmail '{actual_email}'."
                        }

        # 3. Check for domain typosquatting against the organization domain
        if "@" in actual_email and db:
            sender_domain = actual_email.split("@")[-1].lower()
            stmt_admin = select(User).where(User.role == "ADMIN")
            admins = (await db.execute(stmt_admin)).scalars().all()
            for admin in admins:
                if admin.email and "@" in admin.email:
                    corp_domain = admin.email.split("@")[-1].lower()
                    if sender_domain != corp_domain and len(sender_domain) > 4 and len(corp_domain) > 4:
                        dist = self._levenshtein(sender_domain, corp_domain)
                        # If domain is 1 or 2 character edits away from legitimate domain
                        if 1 <= dist <= 2:
                            return {
                                "is_impersonation": True,
                                "type": "TYPOSQUATTING_DOMAIN",
                                "target_domain": corp_domain,
                                "actual_sender": actual_email,
                                "reason": f"Domain Typosquatting Detected: Sender domain '{sender_domain}' is a visual lookalike of corporate domain '{corp_domain}' (edit distance: {dist})."
                            }

        return None


bec_engine = BECDefenseEngine()
