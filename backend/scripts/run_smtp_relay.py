import asyncio
import email
import sys
from pathlib import Path
from email import policy

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from aiosmtpd.controller import Controller
from mailguard_app.services.scanner import mail_scanner
from mailguard_app.database import AsyncSessionLocal
from mailguard_app.models.user import User
from sqlalchemy import select


class MailguardSMTPHandler:
    async def handle_DATA(self, server, session, envelope):
        peer = session.peer
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        data = envelope.content

        msg = email.message_from_bytes(data, policy=policy.default)
        subject = msg.get("subject", "No Subject")

        body_plain = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get("Content-Disposition", ""))

                if "attachment" in cdispo:
                    fname = part.get_filename() or "attachment.bin"
                    attachments.append({
                        "filename": fname,
                        "content_type": ctype,
                        "file_size": len(part.get_payload(decode=True) or b"")
                    })
                elif ctype == "text/plain":
                    body_plain = part.get_content()
                elif ctype == "text/html":
                    body_html = part.get_content()
        else:
            ctype = msg.get_content_type()
            if ctype == "text/plain":
                body_plain = msg.get_content()
            elif ctype == "text/html":
                body_html = msg.get_content()

        async with AsyncSessionLocal() as db_session:
            for rcpt in rcpt_tos:
                user = (await db_session.execute(select(User).where(User.email == rcpt))).scalar_one_or_none()
                target_user_id = user.id if user else 1

                await mail_scanner.scan_and_ingest_email(
                    user_id=target_user_id,
                    sender=mail_from,
                    recipient=rcpt,
                    subject=subject,
                    body_plain=body_plain,
                    body_html=body_html,
                    attachments_meta=attachments,
                    client_ip=peer[0] if peer else "127.0.0.1",
                    db=db_session
                )

        return "250 Message accepted for security inspection"


def run_relay(host: str = "127.0.0.1", port: int = 8025):
    handler = MailguardSMTPHandler()
    controller = Controller(handler, hostname=host, port=port)
    controller.start()
    print(f"Mailguard SMTP Relay running on {host}:{port}")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()


if __name__ == "__main__":
    run_relay()
