from fastapi import APIRouter, Query, Response
from fastapi.responses import RedirectResponse, HTMLResponse
from mailguard_app.services.safelinks import safelinks_service
import urllib.parse
import html

router = APIRouter(prefix="/safelinks", tags=["SafeLinks"])


@router.get("/inspect")
async def inspect_url(url: str = Query(..., description="Target URL to inspect for threats")):
    """Inspects a target URL and returns real-time reputation analysis."""
    result = safelinks_service.inspect_url(url)
    return result


@router.get("/redirect")
async def safelinks_redirect(url: str = Query(..., description="Target URL to navigate to safely")):
    """Time-of-click URL reputation inspection and redirection gateway."""
    decoded_url = urllib.parse.unquote(url)
    inspection = safelinks_service.inspect_url(decoded_url)

    if inspection["is_safe"]:
        return RedirectResponse(url=decoded_url, status_code=302)

    # If the URL is flagged as MALICIOUS or SUSPICIOUS, display the Mailguard SafeLinks Warning Intercept Page
    escaped_url = html.escape(decoded_url)
    escaped_reason = html.escape(inspection.get("reason", "Malicious or suspicious destination detected."))
    threat_level = inspection.get("threat_level", "MALICIOUS")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mailguard SafeLinks - Navigation Blocked</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background-color: #0b0f19;
            color: #f1f5f9;
            font-family: 'Inter', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 24px;
        }}
        .card {{
            background: rgba(18, 24, 38, 0.95);
            border: 1px solid rgba(239, 68, 68, 0.4);
            box-shadow: 0 20px 45px rgba(239, 68, 68, 0.15);
            border-radius: 16px;
            max-width: 620px;
            width: 100%;
            padding: 40px;
            text-align: center;
        }}
        .icon-badge {{
            width: 72px;
            height: 72px;
            background: rgba(239, 68, 68, 0.15);
            border: 2px solid #ef4444;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            margin: 0 auto 24px;
        }}
        h1 {{
            font-size: 24px;
            font-weight: 800;
            color: #ef4444;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }}
        p.subtitle {{
            color: #94a3b8;
            font-size: 14px;
            margin-bottom: 24px;
            line-height: 1.6;
        }}
        .threat-box {{
            background: rgba(239, 68, 68, 0.08);
            border-left: 4px solid #ef4444;
            padding: 16px;
            border-radius: 8px;
            text-align: left;
            margin-bottom: 24px;
        }}
        .threat-box .label {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: #ef4444;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .threat-box .reason {{
            font-size: 13px;
            color: #f87171;
            font-weight: 600;
        }}
        .url-box {{
            background: #060911;
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 12px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 12px;
            color: #cbd5e1;
            word-break: break-all;
            text-align: left;
            margin-bottom: 28px;
        }}
        .actions {{
            display: flex;
            gap: 12px;
            justify-content: center;
        }}
        .btn-primary {{
            background: #2563eb;
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s;
        }}
        .btn-primary:hover {{
            background: #1d4ed8;
            transform: translateY(-1px);
        }}
        .brand {{
            margin-top: 28px;
            font-size: 12px;
            color: #475569;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon-badge">🛡️</div>
        <h1>Dangerous Destination Blocked</h1>
        <p class="subtitle">Mailguard SafeLinks intercepted this link because our real-time reputation engine classified it as a high-risk security threat.</p>
        
        <div class="threat-box">
            <div class="label">Threat Classification: {threat_level}</div>
            <div class="reason">{escaped_reason}</div>
        </div>

        <div class="url-box">
            Blocked URL: {escaped_url}
        </div>

        <div class="actions">
            <a href="/portal/employee" class="btn-primary">Return to Safe Portal</a>
        </div>

        <div class="brand">
            Protected in real-time by Mailguard SafeLinks Gateway
        </div>
    </div>
</body>
</html>
"""
    return HTMLResponse(content=html_content, status_code=200)
