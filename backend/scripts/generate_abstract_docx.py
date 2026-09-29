import os
import sys
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, hex_color):
    """Sets background color for a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tc_pr.append(shd)

def set_cell_margins(cell, top=120, bottom=120, left=150, right=150):
    """Sets cell padding in dxa (1 pt = 20 dxa)."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
    tc_pr.append(tcMar)

def add_callout(doc, text, title="IMPORTANT NOTICE", border_hex="2563EB", bg_hex="EFF6FF", text_hex="1E3A8A"):
    """Adds a callout box."""
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.5)
    set_cell_background(cell, bg_hex)
    set_cell_margins(cell, top=160, bottom=160, left=200, right=200)
    
    # Left border styling
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'<w:top w:val="none"/>'
        f'<w:left w:val="single" w:sz="24" w:space="0" w:color="{border_hex}"/>'
        f'<w:bottom w:val="none"/>'
        f'<w:right w:val="none"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(4)
    run_title = p.add_run(f"{title}\n")
    run_title.bold = True
    run_title.font.name = 'Arial'
    run_title.font.size = Pt(10.5)
    run_title.font.color.rgb = RGBColor.from_string(border_hex)
    
    run_body = p.add_run(text)
    run_body.font.name = 'Arial'
    run_body.font.size = Pt(9.5)
    run_body.font.color.rgb = RGBColor.from_string(text_hex)
    
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

def style_table(table, header_bg="1E293B", alt_row_bg="F8FAFC"):
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(table.rows):
        # Prevent row split across pages
        trPr = row._tr.get_or_add_trPr()
        trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))
        
        for cell in row.cells:
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            set_cell_margins(cell, top=120, bottom=120, left=140, right=140)
            if i == 0:
                set_cell_background(cell, header_bg)
                for p in cell.paragraphs:
                    p.paragraph_format.space_before = Pt(2)
                    p.paragraph_format.space_after = Pt(2)
                    for r in p.runs:
                        r.bold = True
                        r.font.name = 'Arial'
                        r.font.size = Pt(9.5)
                        r.font.color.rgb = RGBColor(255, 255, 255)
            else:
                if i % 2 == 0 and alt_row_bg:
                    set_cell_background(cell, alt_row_bg)
                for p in cell.paragraphs:
                    p.paragraph_format.space_before = Pt(2)
                    p.paragraph_format.space_after = Pt(2)
                    for r in p.runs:
                        r.font.name = 'Arial'
                        r.font.size = Pt(9)
                        if not r.font.color.rgb:
                            r.font.color.rgb = RGBColor(51, 65, 85)

def build_abstract_document():
    doc = Document()

    # Configure Margins
    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)

    # Document Header / Title
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(12)
    p_title.paragraph_format.space_after = Pt(4)
    run_title = p_title.add_run("MAILGUARD 🛡️")
    run_title.bold = True
    run_title.font.name = 'Arial'
    run_title.font.size = Pt(26)
    run_title.font.color.rgb = RGBColor(15, 23, 42)

    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(14)
    run_sub = p_sub.add_run("Enterprise-Grade Secure Email Gateway (SEG) — Complete Project Abstract, Architectural Specification, Function Reference & Verification Manual")
    run_sub.font.name = 'Arial'
    run_sub.font.size = Pt(12)
    run_sub.font.color.rgb = RGBColor(71, 85, 105)

    # Metadata Bar Table
    meta_table = doc.add_table(rows=1, cols=4)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_cols = [
        ("PROJECT VERSION", "1.0 Enterprise (Phases 1–7)"),
        ("CORE FRAMEWORK", "FastAPI / Python 3.11+"),
        ("DATABASE / CACHE", "PostgreSQL 16 & Redis 7"),
        ("STATUS", "37/37 Tests Passing (100%)")
    ]
    for i, (k, v) in enumerate(meta_cols):
        cell = meta_table.cell(0, i)
        set_cell_background(cell, "F1F5F9")
        set_cell_margins(cell, top=100, bottom=100, left=100, right=100)
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        r_k = p.add_run(f"{k}\n")
        r_k.bold = True
        r_k.font.size = Pt(7.5)
        r_k.font.color.rgb = RGBColor(100, 116, 139)
        r_v = p.add_run(v)
        r_v.bold = True
        r_v.font.size = Pt(8.5)
        r_v.font.color.rgb = RGBColor(15, 23, 42)

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # -------------------------------------------------------------
    # SECTION 1: FULL FORM GLOSSARY & TERMINOLOGY
    # -------------------------------------------------------------
    h1 = doc.add_heading("1. Comprehensive Full-Form Glossary & Terminology", level=1)
    h1.paragraph_format.space_before = Pt(16)
    h1.paragraph_format.space_after = Pt(6)

    p_gloss_intro = doc.add_paragraph(
        "To ensure clarity across enterprise stakeholders, security engineers, and developers, "
        "the table below documents every acronym, abbreviation, and specialized terminology used across Mailguard:"
    )
    p_gloss_intro.paragraph_format.space_after = Pt(8)

    glossary_data = [
        ("SEG", "Secure Email Gateway", "A specialized cyber defense gateway that intercepts, analyzes, filters, and quarantines inbound and outbound emails to eliminate malware, spam, and targeted attacks before reaching user inboxes."),
        ("BEC", "Business Email Compromise", "A sophisticated social engineering attack where bad actors impersonate executives, CEOs, CFOs, or corporate vendors to initiate unauthorized financial transfers or steal sensitive data."),
        ("SafeLinks", "Time-of-Click URL Defense", "A real-time link protection engine that rewrites email hyperlinks to redirect through a security gateway, inspecting the destination reputation dynamically at the exact instant the user clicks."),
        ("NLP", "Natural Language Processing", "Computational analysis of natural language text to identify intent, high-urgency language, extortion triggers, credential harvesting keywords, and psychological coercion."),
        ("ML", "Machine Learning", "Statistical algorithms (e.g., Logistic Regression, Naive Bayes) trained on historical threat corpora to classify unseen emails based on multidimensional feature vectors."),
        ("TF-IDF", "Term Frequency - Inverse Document Frequency", "A numerical statistic that reflects how important a word is to an email relative to the entire dataset corpus, used for machine learning vectorization."),
        ("DLP", "Data Loss Prevention", "A defensive subsystem that monitors, detects, and redacts sensitive data (e.g., PAN Cards, Aadhaar IDs, SSNs, and Credit Cards) to prevent intellectual property and financial leaks."),
        ("SPF", "Sender Policy Framework", "An RFC-standardized DNS record (v=spf1) declaring which mail servers and IP addresses are authorized to send emails on behalf of a specific domain."),
        ("DKIM", "DomainKeys Identified Mail", "A cryptographic authentication mechanism (RFC 6376) attaching a digital signature to email headers, verified using the sender's public DNS key."),
        ("DMARC", "Domain-based Message Authentication, Reporting & Conformance", "A policy framework (v=DMARC1) that unites SPF and DKIM, dictating how receivers should handle authentication failures (none, quarantine, reject)."),
        ("RFC", "Request for Comments", "Authoritative technical specification standards developed by the Internet Engineering Task Force (IETF), such as RFC 8601 for email authentication results."),
        ("SOC", "Security Operations Center", "The centralized centralized security department and portal used by security analysts and administrators to monitor live threats, audit incidents, and manage quarantines."),
        ("JWT", "JSON Web Token", "A compact, URL-safe standard (RFC 7519) representing cryptographically signed claims for stateless API authentication and user session management."),
        ("RBAC", "Role-Based Access Control", "An access restriction architecture enforcing strict permission boundaries between administrative SOC operators and standard enterprise employees."),
        ("MIME", "Multipurpose Internet Mail Extensions", "The Internet standard (RFC 2045) extending email format to support plain text, rich HTML, and binary file attachments."),
        ("TLD", "Top-Level Domain", "The highest level in the hierarchical Domain Name System (e.g., .xyz, .top, .com), monitored by SafeLinks for abusive reputation extensions."),
        ("PAN", "Permanent Account Number", "A 10-digit alphanumeric Indian tax identification number (e.g., ABCDE1234F) protected under DLP compliance engines."),
        ("SSN", "Social Security Number", "A 9-digit United States identity identifier (e.g., 123-45-6789) protected under DLP privacy regulations."),
        ("OCR", "Optical Character Recognition", "Technology converting image data and scanned attachment graphics into searchable and analyzable textual streams."),
        ("ASGI", "Asynchronous Server Gateway Interface", "The modern Python asynchronous standard enabling high-throughput concurrent WebSocket, HTTP, and background worker processing in FastAPI.")
    ]

    gloss_table = doc.add_table(rows=len(glossary_data) + 1, cols=3)
    gloss_table.rows[0].cells[0].paragraphs[0].add_run("Acronym")
    gloss_table.rows[0].cells[1].paragraphs[0].add_run("Full Form")
    gloss_table.rows[0].cells[2].paragraphs[0].add_run("Technical Definition & Role in Mailguard")

    for idx, (acr, full, defn) in enumerate(glossary_data):
        row = gloss_table.rows[idx + 1]
        row.cells[0].paragraphs[0].add_run(acr).bold = True
        row.cells[1].paragraphs[0].add_run(full).bold = True
        row.cells[2].paragraphs[0].add_run(defn)

    style_table(gloss_table)
    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # -------------------------------------------------------------
    # SECTION 2: EXECUTIVE ABSTRACT & VALUE PROPOSITION
    # -------------------------------------------------------------
    h2 = doc.add_heading("2. Project Executive Abstract & Architectural Overview", level=1)
    h2.paragraph_format.space_before = Pt(14)
    h2.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "Mailguard is an enterprise-grade Secure Email Gateway (SEG) designed to intercept, analyze, and neutralize "
        "cyber threats across corporate communication streams before they reach employee inboxes. Modern email threats "
        "have evolved past primitive bulk spam into targeted Business Email Compromise (BEC), spear-phishing, weaponized "
        "time-delayed hyperlinks, disguised binary executables, and inadvertent sensitive data leakage (DLP)."
    )

    doc.add_paragraph(
        "Mailguard solves this through a 6-layer defense pipeline combined with advanced Phase 7 enterprise capabilities: "
        "active cryptographic domain validation, trained Scikit-Learn machine learning classifiers, natural language heuristics, "
        "file sandbox inspection, real-time Time-of-Click SafeLinks URL rewriting, executive impersonation defense, "
        "in-email contextual security banner injection, and zero-trust isolation workflows."
    )

    add_callout(
        doc,
        "Every incoming email (via SMTP or live Google Gmail API synchronization) passes sequentially through: "
        "1. Employee & System Pre-Blocking Firewall -> 2. Cryptographic SPF/DKIM/DMARC Authentication -> "
        "3. NLP Threat Heuristics -> 4. ML TF-IDF Classifiers -> 5. Sandbox Attachment Magic Bytes Analyzer -> "
        "6. DLP Inspection -> 7. Anti-BEC Impersonation & SafeLinks Rewriting -> Isolation & Quarantine.",
        title="CORE SEQUENTIAL DEFENSE PIPELINE",
        border_hex="059669",
        bg_hex="ECFDF5",
        text_hex="065F46"
    )

    # -------------------------------------------------------------
    # SECTION 3: PHASE-BY-PHASE TECHNICAL SPECIFICATION
    # -------------------------------------------------------------
    h3 = doc.add_heading("3. Comprehensive Phase-by-Phase Technical Specification", level=1)
    h3.paragraph_format.space_before = Pt(14)
    h3.paragraph_format.space_after = Pt(6)

    phases = [
        ("Phase 1: Architecture, Core Infrastructure & Database Models",
         "Establishes the async FastAPI application foundation, high-performance database schema using SQLAlchemy ORM (compatible with SQLite and PostgreSQL), Alembic migration framework, Pydantic data schemas, JWT token signing, PBKDF2-SHA256 password hashing, and role-based access control (ADMIN vs. EMPLOYEE). Includes models for Users, Active Sessions, Emails, Attachments, ScanResults, Quarantines, PreventionRules, Policies, DLPIncidents, and AuditLogs."),
        
        ("Phase 2: Machine Learning Classifiers & Threat Vector Models",
         "Implements dual Scikit-Learn machine learning pipelines trained on real-world email corpora: (1) Spam Classifier utilizing Multinomial Naive Bayes, and (2) Phishing Classifier utilizing Logistic Regression with TF-IDF n-gram vectorization. Features an in-memory Model Registry providing cross-validated performance metrics (Accuracy, Precision, Recall, F1 Score) and one-click live retraining."),
        
        ("Phase 3: Threat Inspection Engines & Firewall Layers",
         "Delivers the deep inspection engines: (1) Employee and System Pre-Blocking Rule Engine (domain, sender, keyword, regex matching); (2) RFC 8601 Domain Authentication Engine verifying live DNS SPF (v=spf1), DMARC (v=DMARC1), and DKIM signatures; (3) NLP Threat Heuristic Engine scoring urgency, financial coercion, and extortion; (4) Attachment Sandbox Analyzer inspecting MD5/SHA256 hashes, MIME types, and magic bytes (blocking disguised Windows MZ or Linux ELF binaries); and (5) DLP Engine redacting Credit Cards, PAN, Aadhaar, and SSNs."),
        
        ("Phase 4: Unified REST API Gateway",
         "Exposes modular, secure REST endpoints under /api/v1 for authentication (/auth), email scanning (/emails), prevention rule management (/prevention), quarantine administration (/quarantine), user lifecycle (/admin), model registry & retraining (/ml-models), system policies (/policies), DLP incidents (/dlp), feedback collection (/feedback), audit trails (/audit), and real-time dashboard analytics (/dashboard)."),
        
        ("Phase 5: Background Threat Neutralization & Gmail Sync Worker",
         "Implements a background daemon utilizing an aggressive 5-second polling cycle with Google OAuth2 (https://mail.google.com/). It inspects all inbound employee emails in real-time; when a threat is identified, it permanently deletes the message from Gmail before the employee can view or open it, air-gapping the threat in Mailguard's database."),
        
        ("Phase 6: Enterprise Portals & Visual Security Interfaces",
         "Delivers two production web interfaces with modern aesthetics: (1) SOC Security Operations Admin Portal offering real-time threat dashboards, active session monitoring with one-click revocation, live ML model tester, quarantine release manager, DLP log viewer, and audit logs; and (2) Employee Prevention Portal enabling users to inspect their personal inbox, manage pre-blocking filters, manually scan suspicious emails, and view quarantined emails in isolated plain-text or sandboxed HTML preview modals."),
        
        ("Phase 7: Advanced Enterprise Features (HIGHLIGHTED)",
         "Transforms Mailguard into a commercial enterprise competitor with 4 critical capabilities:\n"
         "• Executive / VIP Impersonation Defense (Anti-BEC): Real-time detection of display name spoofing, executive role title hijacking (CEO, CFO, HR Director, Payroll), and typosquatting lookalike domains.\n"
         "• Time-of-Click SafeLinks (URL Rewriting): Automatic inbound hyperlink transformation to route through Mailguard's reputation gateway, blocking direct IP hosts, abusive TLDs, and credential harvesting paths at click-time.\n"
         "• In-Email Security Warning Banners: Dynamic HTML warning header injection (Critical Red for BEC, Alert Amber for Suspicious/Phishing, and Notice Blue for External Senders).\n"
         "• Production Deployment Packaging: Complete multi-container orchestration with Dockerfile and docker-compose.yml linking Mailguard, PostgreSQL 16, and Redis 7.")
    ]

    for p_title, p_desc in phases:
        p_p = doc.add_paragraph()
        p_p.paragraph_format.space_before = Pt(8)
        p_p.paragraph_format.space_after = Pt(2)
        r_pt = p_p.add_run(f"📦 {p_title}")
        r_pt.bold = True
        r_pt.font.name = 'Arial'
        r_pt.font.size = Pt(11)
        r_pt.font.color.rgb = RGBColor(30, 41, 59)
        
        p_pd = doc.add_paragraph(p_desc)
        p_pd.paragraph_format.space_after = Pt(6)

    # -------------------------------------------------------------
    # SECTION 4: DEEP DIVE INTO PHASE 7 ADVANCED ENTERPRISE FEATURES
    # -------------------------------------------------------------
    h4 = doc.add_heading("4. Deep Dive: Phase 7 Advanced Enterprise Features (Highlighted)", level=1)
    h4.paragraph_format.space_before = Pt(14)
    h4.paragraph_format.space_after = Pt(6)

    add_callout(
        doc,
        "Phase 7 elevates Mailguard from a defensive scanner into an active enterprise defense platform with real-time "
        "link rewriting, executive impersonation heuristics, visual email warnings, and containerized multi-tier orchestration.",
        title="🌟 PHASE 7 COMMERCIAL ENTERPRISE CAPABILITIES",
        border_hex="7C3AED",
        bg_hex="F5F3FF",
        text_hex="5B21B6"
    )

    # 4.1 BEC
    doc.add_heading("4.1 Executive / VIP Impersonation Defense (Anti-BEC Engine)", level=2)
    doc.add_paragraph(
        "Business Email Compromise (BEC) attacks bypass traditional signature filters by using socially engineered text from external "
        "free email accounts claiming to be corporate executives. The BEC Defense Engine (bec_defense.py) prevents this via 3 specialized algorithms:"
    )
    doc.add_paragraph("1. Display Name Spoofing: Matches the inbound display name (RFC 5322) against active corporate executives and administrators. If the name matches an internal leader but originates from an external address, it is quarantined immediately.")
    doc.add_paragraph("2. Executive Role Title Hijacking: Inspects display names and email local-parts (e.g., ceo.desk@yahoo.com, cfo.office@gmail.com, payroll.dept@outlook.com) for executive keywords (CEO, CFO, COO, CTO, President, Payroll, HR Director) sent from public webmail domains.")
    doc.add_paragraph("3. Domain Typosquatting / Lookalike Detection: Employs Levenshtein edit distance algorithms comparing sender domains against the corporate domain, identifying visual typosquats (e.g., myc0rpdomain.com vs mycorpdomain.com with edit distance 1).")

    # 4.2 SafeLinks
    doc.add_heading("4.2 Time-of-Click SafeLinks (URL Rewriting & Real-Time Gateway)", level=2)
    doc.add_paragraph(
        "Attackers frequently send clean emails containing benign links that are later weaponized into phishing sites after passing gateway inspection. "
        "Mailguard SafeLinks (safelinks.py) neutralizes this by:"
    )
    doc.add_paragraph("• Automatic URL Rewriting: Rewrites all inbound email links (both plain text and HTML) to route through /api/v1/safelinks/redirect?url=<encoded_target>.")
    doc.add_paragraph("• Real-Time Reputation Inspection: When the employee clicks the link, the gateway inspects the destination for direct IP hosts (e.g. http://185.220.101.5), high-risk TLDs (.xyz, .top, .zip, .click, .buzz, .ru), non-standard web ports, and credential harvesting paths (/login, /signin, /password_reset, /verify).")
    doc.add_paragraph("• Navigation Intercept Screen: If malicious, navigation is blocked and an aesthetically styled red warning page is displayed. If verified clean, the user is redirected (HTTP 302) seamlessly.")

    # 4.3 In-Email Banners
    doc.add_heading("4.3 In-Email Security Warning Banners", level=2)
    doc.add_paragraph(
        "To provide instant visual situational awareness, Mailguard dynamically injects HTML security banners (banner_injection.py) "
        "directly into the top of inbound emails and portal inspection modals:"
    )
    doc.add_paragraph("• 🚨 Critical Red Banner (BEC Impersonation): Injected when executive spoofing is detected, warning users never to wire funds, reply, or purchase gift cards.")
    doc.add_paragraph("• ⚠️ Alert Amber Banner (Suspicious / Phishing): Injected when ML or NLP flags elevated threat signals, prompting identity verification before opening attachments.")
    doc.add_paragraph("• 🛡️ Notice Blue Banner (External Sender): Injected on all clean external emails, notifying employees that the message originated outside the corporate network.")

    # 4.4 Docker Packaging
    doc.add_heading("4.4 Production Deployment Packaging (Docker & Docker Compose)", level=2)
    doc.add_paragraph(
        "Mailguard is packaged for enterprise production via Dockerfile and multi-service docker-compose.yml orchestration:"
    )
    doc.add_paragraph("• mailguard_gateway: Containerized FastAPI gateway service with automatic database migrations and health checks.")
    doc.add_paragraph("• mailguard_postgres: Enterprise PostgreSQL 16 relational database with dedicated health checks and persistent volume storage.")
    doc.add_paragraph("• mailguard_redis: In-memory Redis 7 message broker and cache service with healthcheck polling.")

    # -------------------------------------------------------------
    # SECTION 5: FUNCTION DICTIONARY & CODE LOGIC
    # -------------------------------------------------------------
    h5 = doc.add_heading("5. Comprehensive Function Dictionary & Code Logic Reference", level=1)
    h5.paragraph_format.space_before = Pt(14)
    h5.paragraph_format.space_after = Pt(6)

    fn_data = [
        ("evaluate_impersonation", "bec_defense.py", "raw_sender, subject, body, db", "Dict / None", "Analyzes sender display name, email local-part, and domain against registered users and executive keywords to detect BEC impersonation and typosquatting."),
        ("rewrite_html_links", "safelinks.py", "html_content, api_base", "str", "Parses all <a> hyperlinks in HTML email bodies and replaces href attributes with the SafeLinks redirect gateway URL."),
        ("rewrite_plain_links", "safelinks.py", "plain_content, api_base", "str", "Regex-inspects plain text email bodies and wraps all raw URLs with the SafeLinks redirect URL."),
        ("inspect_url", "safelinks.py", "target_url", "Dict", "Evaluates destination URL reputation dynamically against direct IP hosts, suspicious TLDs, non-standard ports, and credential harvesting paths."),
        ("inject_banner", "banner_injection.py", "html_body, threat_verdict, bec_hit, is_external", "str", "Constructs and injects responsive, color-coded HTML warning banners into the top of email bodies."),
        ("scan_and_ingest_email", "scanner.py", "user_id, sender, recipient, subject, body_plain, body_html, ...", "Dict", "Master scanner orchestration pipeline executing all 6 defense layers, BEC checks, SafeLinks rewriting, banner injection, database persistence, and Gmail quarantine."),
        ("evaluate_employee_prevention", "policy_engine.py", "user_id, sender, subject, body, db", "Dict / None", "Evaluates employee self-service firewall rules (block domain, sender, keyword, regex)."),
        ("evaluate_all", "auth_check.py", "sender, client_ip, raw_headers", "Dict", "Performs live cryptographic DNS SPF, DMARC, and DKIM authentication verification."),
        ("predict_all", "predict.py", "subject, body", "Dict", "Executes TF-IDF feature extraction and queries Spam Naive Bayes and Phishing Logistic Regression models with heuristic adjustments."),
        ("analyze", "nlp_check.py", "subject, body", "Dict", "Scans text for urgent call-to-actions, financial extortion, gift card scams, and credential harvesting indicators."),
        ("inspect_text", "dlp_check.py", "text", "List[Dict]", "Scans email text for sensitive PII/financial data (Credit Cards, PAN, Aadhaar, SSN) and creates masked sample records."),
        ("analyze_file", "sandbox_check.py", "filename, content_type, file_path", "Dict", "Inspects attachment MD5/SHA256 hashes, double-extensions, and binary magic bytes (MZ/ELF)."),
        ("isolate_and_quarantine", "isolation.py", "email, reason, isolation_level, db", "QuarantineRecord", "Isolates malicious emails into quarantine with designated air-gap levels (QUARANTINED / AIR_GAPPED)."),
        ("sync_and_filter_user_emails", "gmail_sync.py", "user, max_results, db", "List[Dict]", "Polls user Gmail inbox via Google OAuth2, ingests new messages, and deletes identified threats permanently.")
    ]

    fn_table = doc.add_table(rows=len(fn_data) + 1, cols=4)
    fn_table.rows[0].cells[0].paragraphs[0].add_run("Function Name")
    fn_table.rows[0].cells[1].paragraphs[0].add_run("Module / File")
    fn_table.rows[0].cells[2].paragraphs[0].add_run("Signature & Returns")
    fn_table.rows[0].cells[3].paragraphs[0].add_run("Core Logic & Business Purpose")

    for idx, (fn, mod, sig, ret, purp) in enumerate(fn_data):
        row = fn_table.rows[idx + 1]
        row.cells[0].paragraphs[0].add_run(fn).bold = True
        row.cells[1].paragraphs[0].add_run(mod)
        row.cells[2].paragraphs[0].add_run(f"({sig}) -> {ret}")
        row.cells[3].paragraphs[0].add_run(purp)

    style_table(fn_table)
    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # -------------------------------------------------------------
    # SECTION 6: MANUAL TESTING GUIDE & TEST CASES
    # -------------------------------------------------------------
    h6 = doc.add_heading("6. Step-by-Step Manual Testing Guide & Test Cases", level=1)
    h6.paragraph_format.space_before = Pt(14)
    h6.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "To validate all system capabilities end-to-end, follow the manual testing procedures below "
        "using the Employee Portal (http://localhost:8000/portal/employee) or SOC Admin Portal (http://localhost:8000/portal/admin):"
    )

    test_cases = [
        ("TC-01", "Executive Title / Role Impersonation (Anti-BEC)",
         "In Employee Portal -> Manual Email Scanner, enter:\n• Sender: ceo.desk@yahoo.com\n• Subject: Urgent: Wire transfer required\n• Body: Please execute this vendor invoice immediately.",
         "• Verdict: BEC_IMPERSONATION (Red Badge)\n• Status: QUARANTINED / ISOLATED\n• Review Modal: Displays Critical Red Warning Header ('🚨 Critical Warning: Executive Impersonation... VIP Title Spoofing')."),
        
        ("TC-02", "Display Name Spoofing of Corporate Leader",
         "In Manual Email Scanner, enter:\n• Sender: \"System Administrator\" <attacker.scammer@gmail.com>\n• Subject: Account Re-verification\n• Body: Update credentials immediately.",
         "• Verdict: BEC_IMPERSONATION\n• Status: QUARANTINED\n• Review Modal: Flags that display name mimics internal administrator but originates from external Gmail."),
        
        ("TC-03", "Time-of-Click SafeLinks URL Rewriting & Threat Intercept",
         "1. In Manual Scanner, ingest an email with body: Click <a href=\"https://fake-login.xyz/password_reset\">here</a>\n2. Open Review modal -> Inspect HTML source.\n3. Open in browser: http://localhost:8000/api/v1/safelinks/redirect?url=https://fake-login.xyz/password_reset",
         "1. Hyperlink is automatically rewritten to /api/v1/safelinks/redirect?url=...\n2. Browser navigates to the red Mailguard SafeLinks Warning Intercept Page ('Dangerous Destination Blocked')."),
        
        ("TC-04", "Time-of-Click SafeLinks Clean URL Redirection",
         "Open in browser: http://localhost:8000/api/v1/safelinks/redirect?url=https://github.com",
         "Gateway verifies URL reputation as clean and seamlessly redirects (HTTP 302) to GitHub."),
        
        ("TC-05", "In-Email Security Warning Banner (External / Phishing)",
         "Ingest a normal external email:\n• Sender: newsletter@partner.com\n• Subject: Monthly Tech Digest\n• Body: Here is the digest for September.",
         "• Verdict: CLEAN\n• Review Modal: Displays Blue Notice Header ('🛡️ Notice: Inbound External Sender: This message originated outside your enterprise.')."),
        
        ("TC-06", "Employee Self-Service Prevention Rules (Pre-blocking)",
         "1. Under 'Spam Pre-Blocking Rules', add rule: Rule Type = Block Sender Domain, Pattern = spammer.net\n2. Ingest email from deals@spammer.net.",
         "• Verdict: BLOCKED\n• Isolation Status: PRE_BLOCKED\n• Rule hit count increments automatically."),
        
        ("TC-07", "Attachment Sandbox Executable Detection (MZ Magic Bytes)",
         "Ingest an email with attachment payload.exe (MIME: application/x-msdownload).",
         "• Sandbox Verdict: MALICIOUS\n• Status: QUARANTINED / AIR_GAPPED\n• Reason: Sandbox detected executable binary structure."),
        
        ("TC-08", "Data Loss Prevention (DLP) Card & PAN Redaction",
         "Ingest email with body containing: Employee PAN ABCDE1234F and Card 4111222233334444.",
         "• Verdict: DLP_VIOLATION\n• Status: QUARANTINED\n• DLP incident logged with masked sample AB****4F."),
        
        ("TC-09", "ML Model Retraining & Threat Tester in SOC Portal",
         "1. Open Admin Portal -> Machine Learning tab.\n2. Click 'Retrain All Models'.\n3. In 'Live Threat Tester', test: 'Urgent: Your account is suspended. Login to verify.'",
         "1. Models retrain and live cross-validated Accuracy, F1, Precision, and Recall scores update.\n2. Predictor outputs high Phishing/Spam probability and PHISHING verdict."),
        
        ("TC-10", "SOC Quarantine Release Workflow",
         "1. Open Admin Portal -> Quarantine Manager tab.\n2. Locate quarantined email and click 'Release'.",
         "Quarantine record transitions to RELEASED with admin audit attribution.")
    ]

    tc_table = doc.add_table(rows=len(test_cases) + 1, cols=4)
    tc_table.rows[0].cells[0].paragraphs[0].add_run("Case ID")
    tc_table.rows[0].cells[1].paragraphs[0].add_run("Test Feature & Scenario")
    tc_table.rows[0].cells[2].paragraphs[0].add_run("Input Data / Action Steps")
    tc_table.rows[0].cells[3].paragraphs[0].add_run("Expected Output & Verification")

    for idx, (cid, scn, inp, exp) in enumerate(test_cases):
        row = tc_table.rows[idx + 1]
        row.cells[0].paragraphs[0].add_run(cid).bold = True
        row.cells[1].paragraphs[0].add_run(scn).bold = True
        row.cells[2].paragraphs[0].add_run(inp)
        row.cells[3].paragraphs[0].add_run(exp)

    style_table(tc_table)
    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # -------------------------------------------------------------
    # SECTION 7: AUTOMATED TEST SUITE EXECUTION
    # -------------------------------------------------------------
    h7 = doc.add_heading("7. Automated Test Suite Verification (100% Passing)", level=1)
    h7.paragraph_format.space_before = Pt(14)
    h7.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "Mailguard contains a rigorous automated test suite executed via Pytest. "
        "All 37 test cases across all 7 development phases are passing with 100% success rate:"
    )

    test_summary = [
        ("tests/test_phase1.py", "3 Tests", "Database models, JWT encoding/decoding, password hashing, and user creation."),
        ("tests/test_phase2_models.py", "4 Tests", "Spam/Phishing TF-IDF vectorization, ML prediction pipeline, model metrics, and retraining."),
        ("tests/test_phase3_engines.py", "7 Tests", "Domain authentication, NLP heuristics, DLP redaction, sandbox binary check, and isolation."),
        ("tests/test_phase4_api.py", "3 Tests", "REST API endpoints, auth token validation, email ingestion, and prevention rules."),
        ("tests/test_phase5_tasks.py", "5 Tests", "Gmail sync worker, background polling loop, and threat isolation tasks."),
        ("tests/test_phase6_views.py", "5 Tests", "Employee portal views, SOC admin portal views, static assets, and favicon routes."),
        ("tests/test_phase7_enterprise.py", "10 Tests", "BEC display name spoofing, title hijacking, typosquatting, SafeLinks URL inspection, HTML/plain link rewriting, warning banners, and redirect gateway.")
    ]

    ts_table = doc.add_table(rows=len(test_summary) + 1, cols=3)
    ts_table.rows[0].cells[0].paragraphs[0].add_run("Test Suite File")
    ts_table.rows[0].cells[1].paragraphs[0].add_run("Test Count")
    ts_table.rows[0].cells[2].paragraphs[0].add_run("Coverage & Verification Scope")

    for idx, (f, c, s) in enumerate(test_summary):
        row = ts_table.rows[idx + 1]
        row.cells[0].paragraphs[0].add_run(f).bold = True
        row.cells[1].paragraphs[0].add_run(c).bold = True
        row.cells[2].paragraphs[0].add_run(s)

    style_table(ts_table)
    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    add_callout(
        doc,
        "Pytest Execution Result: 37 passed in 30.25s (100% Pass Rate). All phases validated and verified.",
        title="AUTOMATED TEST SUITE STATUS",
        border_hex="10B981",
        bg_hex="ECFDF5",
        text_hex="065F46"
    )

    # Save Document
    out_path = r"C:\Users\dororo\MyFiles\CODES\Mailguard\Mailguard_Comprehensive_Abstract.docx"
    doc.save(out_path)
    print(f"Document successfully created at: {out_path}")

if __name__ == "__main__":
    build_abstract_document()
