import os
import hashlib
from typing import Dict, Any, List


class SandboxAnalyzer:
    DANGEROUS_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".pif", ".jar",
        ".iso", ".img", ".hta", ".cpl", ".msc", ".inf", ".wsf", ".msi"
    }

    SUSPICIOUS_MIME_TYPES = {
        "application/x-msdownload", "application/x-executable",
        "application/x-dosexec", "application/x-msdos-program",
        "application/x-bat", "application/x-vbs"
    }

    def compute_hashes(self, file_path: str) -> Dict[str, str]:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        if not os.path.exists(file_path):
            return {"md5": "", "sha256": ""}

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)

        return {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }

    def analyze_file(self, filename: str, content_type: str, file_path: str = None) -> Dict[str, Any]:
        ext = os.path.splitext(filename)[1].lower()
        is_malicious = False
        verdict = "CLEAN"
        reasons: List[str] = []

        # Check for double extension evasion attempts (e.g. report.pdf.exe)
        parts = filename.lower().split(".")
        if len(parts) > 2 and f".{parts[-1]}" in self.DANGEROUS_EXTENSIONS:
            is_malicious = True
            verdict = "MALICIOUS"
            reasons.append(f"Deceptive double-extension detected: {filename}")

        if ext in self.DANGEROUS_EXTENSIONS:
            is_malicious = True
            verdict = "MALICIOUS"
            reasons.append(f"Dangerous executable extension detected: {ext}")

        if content_type in self.SUSPICIOUS_MIME_TYPES:
            is_malicious = True
            verdict = "MALICIOUS"
            reasons.append(f"Suspicious MIME type detected: {content_type}")

        # Magic bytes inspection to detect disguised executables
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "rb") as f:
                    header = f.read(16)
                    # Check for Windows PE executable header (MZ) disguised as document/image
                    if header.startswith(b"MZ") and ext not in [".exe", ".dll", ".sys"]:
                        is_malicious = True
                        verdict = "MALICIOUS"
                        reasons.append("Disguised Windows executable: magic bytes 'MZ' mismatch declared extension")
                    # Check for Linux ELF binary header (\x7fELF)
                    elif header.startswith(b"\x7fELF") and ext not in [".so", ".bin"]:
                        is_malicious = True
                        verdict = "MALICIOUS"
                        reasons.append("Disguised Linux ELF binary detected in attachment")
            except Exception:
                pass

        hashes = self.compute_hashes(file_path) if file_path and os.path.exists(file_path) else {"md5": "", "sha256": ""}

        return {
            "filename": filename,
            "extension": ext,
            "content_type": content_type,
            "is_malicious": is_malicious,
            "sandbox_verdict": verdict,
            "reasons": reasons,
            "md5_hash": hashes["md5"],
            "sha256_hash": hashes["sha256"]
        }


sandbox_analyzer = SandboxAnalyzer()
