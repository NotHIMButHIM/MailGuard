import base64
import httpx
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from mailguard_app.models.user import User
from mailguard_app.core.security import refresh_google_access_token
from mailguard_app.core.exceptions import MailguardException


class GmailSyncService:
    def _decode_body(self, payload_data: str) -> str:
        if not payload_data:
            return ""
        try:
            padded = payload_data + "=" * (-len(payload_data) % 4)
            return base64.urlsafe_b64decode(padded.encode("UTF-8")).decode("UTF-8", errors="replace")
        except Exception:
            return ""

    def _extract_parts(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        body_plain = ""
        body_html = ""
        attachments = []

        headers_list = payload.get("headers", [])
        headers_dict = {h.get("name", "").lower(): h.get("value", "") for h in headers_list}

        sender = headers_dict.get("from", "")
        recipient = headers_dict.get("to", "")
        subject = headers_dict.get("subject", "No Subject")
        message_id = headers_dict.get("message-id", "")

        mime_type = payload.get("mimeType", "")
        body_data = payload.get("body", {}).get("data", "")

        if mime_type == "text/plain" and body_data:
            body_plain = self._decode_body(body_data)
        elif mime_type == "text/html" and body_data:
            body_html = self._decode_body(body_data)

        parts = payload.get("parts", [])
        for part in parts:
            part_mime = part.get("mimeType", "")
            part_body = part.get("body", {})
            part_data = part_body.get("data", "")
            filename = part.get("filename", "")

            if filename:
                attachments.append({
                    "filename": filename,
                    "content_type": part_mime,
                    "file_size": part_body.get("size", 0),
                    "attachment_id": part_body.get("attachmentId", "")
                })
            elif part_mime == "text/plain" and part_data:
                body_plain = self._decode_body(part_data)
            elif part_mime == "text/html" and part_data:
                body_html = self._decode_body(part_data)

        return {
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "message_id": message_id,
            "body_plain": body_plain,
            "body_html": body_html,
            "attachments": attachments,
            "raw_headers": headers_dict
        }

    async def _get_valid_access_token(self, user: User, db: Optional[AsyncSession] = None) -> Optional[str]:
        if not user.google_access_token and not user.google_refresh_token:
            return None

        if user.google_access_token:
            return user.google_access_token

        if user.google_refresh_token:
            new_token = await refresh_google_access_token(user.google_refresh_token)
            if new_token and db:
                user.google_access_token = new_token
                await db.commit()
            return new_token

        return None

    async def fetch_recent_messages(
        self,
        user: User,
        max_results: int = 10,
        db: Optional[AsyncSession] = None
    ) -> List[Dict[str, Any]]:
        access_token = await self._get_valid_access_token(user, db)
        if not access_token:
            return []

        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages",
                params={"maxResults": max_results, "includeSpamTrash": True},
                headers={"Authorization": f"Bearer {access_token}"}
            )

            if res.status_code == 401 and user.google_refresh_token:
                new_token = await refresh_google_access_token(user.google_refresh_token)
                if new_token:
                    access_token = new_token
                    if db:
                        user.google_access_token = new_token
                        await db.commit()
                    res = await client.get(
                        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
                        params={"maxResults": max_results, "includeSpamTrash": True},
                        headers={"Authorization": f"Bearer {access_token}"}
                    )

            if res.status_code != 200:
                err_data = {}
                try:
                    err_data = res.json()
                except Exception:
                    pass
                err_msg = err_data.get("error", {}).get("message", res.text)
                raise MailguardException(
                    status_code=res.status_code,
                    detail=f"Google Gmail API error ({res.status_code}): {err_msg}"
                )

            data = res.json()
            messages_meta = data.get("messages", [])
            full_messages = []

            for meta in messages_meta:
                msg_id = meta.get("id")
                msg_res = await client.get(
                    f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}",
                    params={"format": "full"},
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                if msg_res.status_code == 200:
                    msg_json = msg_res.json()
                    parsed = self._extract_parts(msg_json.get("payload", {}))
                    parsed["gmail_message_id"] = msg_id
                    full_messages.append(parsed)

            return full_messages

    async def quarantine_gmail_message(
        self,
        user: User,
        gmail_message_id: str,
        db: Optional[AsyncSession] = None
    ) -> bool:
        """Permanently remove a threat email from Gmail.
        
        Strategy (in order of aggressiveness):
        1. Permanently delete the message (requires gmail.modify scope)
        2. Trash the message (moves to Trash, auto-deleted after 30 days)
        3. Remove from INBOX and SPAM labels (hides it from all views)
        """
        access_token = await self._get_valid_access_token(user, db)
        if not access_token or not gmail_message_id:
            return False

        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {"Authorization": f"Bearer {access_token}"}

            # Attempt 1: Permanent deletion — completely removes from Gmail
            res = await client.delete(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_message_id}",
                headers=headers
            )

            if res.status_code == 401 and user.google_refresh_token:
                new_token = await refresh_google_access_token(user.google_refresh_token)
                if new_token:
                    access_token = new_token
                    if db:
                        user.google_access_token = new_token
                        await db.commit()
                    headers = {"Authorization": f"Bearer {access_token}"}
                    res = await client.delete(
                        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_message_id}",
                        headers=headers
                    )

            if res.status_code in [200, 204]:
                return True

            # Attempt 2: Trash the message
            res = await client.post(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_message_id}/trash",
                headers=headers
            )

            if res.status_code in [200, 204]:
                return True

            # Attempt 3: Remove from all visible labels
            res = await client.post(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_message_id}/modify",
                headers={**headers, "Content-Type": "application/json"},
                json={
                    "removeLabelIds": ["INBOX", "SPAM", "UNREAD", "IMPORTANT", "CATEGORY_PERSONAL",
                                       "CATEGORY_SOCIAL", "CATEGORY_PROMOTIONS", "CATEGORY_UPDATES"]
                }
            )

            return res.status_code in [200, 204]

    async def restore_gmail_message(
        self,
        user: User,
        gmail_message_id: str,
        db: Optional[AsyncSession] = None
    ) -> bool:
        access_token = await self._get_valid_access_token(user, db)
        if not access_token or not gmail_message_id:
            return False

        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.post(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_message_id}/untrash",
                headers={"Authorization": f"Bearer {access_token}"}
            )

            if res.status_code == 401 and user.google_refresh_token:
                new_token = await refresh_google_access_token(user.google_refresh_token)
                if new_token:
                    access_token = new_token
                    if db:
                        user.google_access_token = new_token
                        await db.commit()
                    res = await client.post(
                        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_message_id}/untrash",
                        headers={"Authorization": f"Bearer {access_token}"}
                    )

            await client.post(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_message_id}/modify",
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                json={
                    "removeLabelIds": ["SPAM"],
                    "addLabelIds": ["INBOX"]
                }
            )
            return True

    async def sync_and_filter_user_emails(
        self,
        user: User,
        max_results: int = 15,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        if not db:
            return {"status": "skipped", "synced_count": 0, "filtered_threats": 0}

        messages = await self.fetch_recent_messages(user, max_results=max_results, db=db)
        from mailguard_app.models.email import Email
        from mailguard_app.services.scanner import mail_scanner
        from sqlalchemy import select

        synced_count = 0
        filtered_threats = 0

        for msg in messages:
            msg_id = msg.get("gmail_message_id")
            stmt = select(Email).where(Email.gmail_message_id == msg_id)
            existing = (await db.execute(stmt)).scalar_one_or_none()

            if existing:
                if existing.status in ["QUARANTINED", "BLOCKED"]:
                    try:
                        await self.quarantine_gmail_message(user, msg_id, db=db)
                        filtered_threats += 1
                    except Exception:
                        pass
                continue

            res = await mail_scanner.scan_and_ingest_email(
                user_id=user.id,
                sender=msg.get("sender", ""),
                recipient=msg.get("recipient", user.email),
                subject=msg.get("subject", ""),
                body_plain=msg.get("body_plain", ""),
                body_html=msg.get("body_html", ""),
                gmail_message_id=msg_id,
                attachments_meta=msg.get("attachments", []),
                raw_headers=msg.get("raw_headers", {}),
                db=db
            )
            synced_count += 1
            if res.get("status") in ["QUARANTINED", "BLOCKED"]:
                filtered_threats += 1

        return {
            "status": "completed",
            "synced_count": synced_count,
            "filtered_threats": filtered_threats
        }


gmail_sync_service = GmailSyncService()
