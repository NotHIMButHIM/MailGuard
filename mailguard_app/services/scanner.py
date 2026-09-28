import os
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from mailguard_app.models.user import User
from mailguard_app.models.email import Email, Attachment, ScanResult
from mailguard_app.models.dlp import DLPIncident
from mailguard_app.services.auth_check import auth_checker
from mailguard_app.services.nlp_check import nlp_engine
from mailguard_app.services.dlp_check import dlp_inspector
from mailguard_app.services.sandbox_check import sandbox_analyzer
from mailguard_app.services.policy_engine import policy_engine
from mailguard_app.services.isolation import isolation_engine
from mailguard_app.services.bec_defense import bec_engine
from mailguard_app.services.safelinks import safelinks_service
from mailguard_app.services.banner_injection import banner_injector
from mailguard_app.ml.predict import predictor


class MailScannerService:
    async def scan_and_ingest_email(
        self,
        user_id: int,
        sender: str,
        recipient: str,
        subject: str,
        body_plain: str,
        body_html: str,
        raw_mime_path: Optional[str] = None,
        gmail_message_id: Optional[str] = None,
        attachments_meta: Optional[List[Dict[str, Any]]] = None,
        raw_headers: Optional[Dict[str, str]] = None,
        client_ip: str = "127.0.0.1",
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        prevention_hit = None
        if db:
            prevention_hit = await policy_engine.evaluate_employee_prevention(
                user_id=user_id,
                sender=sender,
                subject=subject,
                body=body_plain,
                db=db
            )

        bec_hit = None
        if db:
            bec_hit = await bec_engine.evaluate_impersonation(
                raw_sender=sender,
                subject=subject,
                body=body_plain,
                db=db
            )

        attachment_names = [a.get("filename", "") for a in (attachments_meta or [])]
        policy_hit = None
        if db:
            policy_hit = await policy_engine.evaluate_system_policies(
                sender=sender,
                subject=subject,
                body=body_plain,
                attachment_names=attachment_names,
                db=db
            )

        auth_verdict = auth_checker.evaluate_all(sender=sender, client_ip=client_ip, raw_headers=raw_headers)
        ml_verdict = predictor.predict_all(subject=subject, body=body_plain)
        nlp_verdict = nlp_engine.analyze(subject=subject, body=body_plain)
        dlp_incidents = dlp_inspector.inspect_text(f"{subject}\n{body_plain}")

        attachment_scans = []
        has_malicious_attachment = False
        for att in (attachments_meta or []):
            res = sandbox_analyzer.analyze_file(
                filename=att.get("filename", "unknown"),
                content_type=att.get("content_type", "application/octet-stream"),
                file_path=att.get("storage_path")
            )
            attachment_scans.append(res)
            if res["is_malicious"]:
                has_malicious_attachment = True

        status = "CLEAN"
        isolation_status = "NONE"
        threat_verdict = "CLEAN"
        reasons = []

        if prevention_hit:
            status = "BLOCKED"
            isolation_status = "PRE_BLOCKED"
            threat_verdict = "BLOCKED"
            reasons.append(prevention_hit["reason"])
        elif bec_hit and bec_hit.get("is_impersonation"):
            status = "QUARANTINED"
            isolation_status = "ISOLATED"
            threat_verdict = "BEC_IMPERSONATION"
            reasons.append(bec_hit.get("reason", "Executive Impersonation Detected"))
        elif policy_hit:
            status = "QUARANTINED"
            isolation_status = "ISOLATED"
            threat_verdict = "POLICY_VIOLATION"
            reasons.append(policy_hit["reason"])
        elif has_malicious_attachment:
            status = "QUARANTINED"
            isolation_status = "ISOLATED"
            threat_verdict = "MALICIOUS"
            reasons.append("Malicious attachment detected in sandbox analysis")
        elif ml_verdict["verdict"] in ["PHISHING", "SPAM"]:
            status = "QUARANTINED"
            isolation_status = "ISOLATED"
            threat_verdict = ml_verdict["verdict"]
            reasons.append(f"ML threat confidence high: {ml_verdict['verdict']}")
        elif dlp_incidents:
            status = "QUARANTINED"
            isolation_status = "ISOLATED"
            threat_verdict = "DLP_VIOLATION"
            reasons.append("Sensitive data leak (PAN/Aadhaar/SSN/Card) detected")
        elif auth_verdict["spf_status"] == "FAIL" or auth_verdict["dmarc_status"] == "FAIL":
            status = "QUARANTINED"
            isolation_status = "ISOLATED"
            threat_verdict = "AUTH_FAILED"
            reasons.append("Email failed SPF/DMARC domain authentication checks")
        elif ml_verdict["verdict"] == "SUSPICIOUS":
            status = "CLEAN"
            isolation_status = "NONE"
            threat_verdict = "SUSPICIOUS"

        import html

        # Auto-generate HTML wrapper for plain-text emails to ensure SafeLinks & Security Banners render
        if not body_html and body_plain:
            escaped_text = html.escape(body_plain).replace("\n", "<br>")
            body_html = f"<div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 14px; line-height: 1.6; color: #334155; padding: 12px;\"><p>{escaped_text}</p></div>"

        # Apply Time-of-Click SafeLinks URL Rewriting
        processed_plain = safelinks_service.rewrite_plain_links(body_plain or "")
        processed_html = safelinks_service.rewrite_html_links(body_html or "")

        # Inject Security Warning Banners for Inbound emails
        if processed_html:
            processed_html = banner_injector.inject_banner(
                html_body=processed_html,
                threat_verdict=threat_verdict,
                bec_hit=bec_hit,
                is_external=True
            )

        email_record = None
        quarantine_record = None

        if db:
            email_record = Email(
                user_id=user_id,
                sender=sender,
                recipient=recipient,
                subject=subject,
                body_plain=processed_plain or body_plain,
                body_html=processed_html or body_html,
                raw_mime_path=raw_mime_path,
                gmail_message_id=gmail_message_id,
                direction="INBOUND",
                status=status,
                isolation_status=isolation_status,
                spam_score=ml_verdict["spam_score"],
                phishing_score=ml_verdict["phishing_score"],
                threat_verdict=threat_verdict
            )
            db.add(email_record)
            await db.commit()
            await db.refresh(email_record)

            scan_result = ScanResult(
                email_id=email_record.id,
                spf_status=auth_verdict["spf_status"],
                dkim_status=auth_verdict["dkim_status"],
                dmarc_status=auth_verdict["dmarc_status"],
                nlp_score=nlp_verdict["nlp_score"],
                dlp_hits=dlp_incidents,
                ocr_extracted_text="",
                sandbox_details={
                    "attachments": attachment_scans,
                    "bec_defense": bec_hit,
                    "safelinks_rewritten": bool(processed_html != body_html or processed_plain != body_plain)
                },
                ml_spam_probability=ml_verdict["spam_score"],
                ml_phishing_probability=ml_verdict["phishing_score"],
                final_verdict=threat_verdict
            )
            db.add(scan_result)

            for att_scan in attachment_scans:
                att_record = Attachment(
                    email_id=email_record.id,
                    filename=att_scan["filename"],
                    content_type=att_scan["content_type"],
                    file_size=0,
                    storage_path=att_scan.get("file_path", ""),
                    md5_hash=att_scan["md5_hash"],
                    sha256_hash=att_scan["sha256_hash"],
                    is_malicious=att_scan["is_malicious"],
                    sandbox_verdict=att_scan["sandbox_verdict"],
                    scan_details=att_scan
                )
                db.add(att_record)

            for dlp_hit in dlp_incidents:
                dlp_rec = DLPIncident(
                    email_id=email_record.id,
                    user_id=user_id,
                    pattern_type=dlp_hit["pattern_type"],
                    matches_count=dlp_hit["matches_count"],
                    severity=dlp_hit["severity"],
                    masked_sample=dlp_hit["masked_sample"]
                )
                db.add(dlp_rec)

            await db.commit()

            if status == "QUARANTINED":
                quarantine_record = await isolation_engine.isolate_and_quarantine(
                    email=email_record,
                    reason="; ".join(reasons) or "Automated threat rule triggered",
                    isolation_level="AIR_GAPPED" if has_malicious_attachment else "QUARANTINED",
                    db=db
                )

            if status in ["QUARANTINED", "BLOCKED"] and gmail_message_id:
                user_obj = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
                if user_obj and user_obj.is_google_user:
                    try:
                        from mailguard_app.services.gmail_sync import gmail_sync_service
                        await gmail_sync_service.quarantine_gmail_message(user_obj, gmail_message_id, db=db)
                    except Exception:
                        pass

        return {
            "email_id": email_record.id if email_record else None,
            "status": status,
            "isolation_status": isolation_status,
            "threat_verdict": threat_verdict,
            "reasons": reasons,
            "auth": auth_verdict,
            "ml": ml_verdict,
            "nlp": nlp_verdict,
            "dlp": dlp_incidents,
            "bec": bec_hit,
            "processed_html": processed_html,
            "processed_plain": processed_plain,
            "attachments": attachment_scans,
            "quarantine_id": quarantine_record.id if quarantine_record else None
        }


mail_scanner = MailScannerService()
