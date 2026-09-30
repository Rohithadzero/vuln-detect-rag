"""Threat screening for user-supplied files and links.

Every check here is deterministic and local: a hash, a magic-byte sniff, the
industry-standard EICAR test signature, and a set of content and URL
heuristics. Nothing is invented. When a finding cannot be proven it is not
reported, and the per-item ``note`` states exactly what was and was not
consulted -- the same honesty rule the scanners follow (see commit
"stop fabricating findings").

An optional VirusTotal reputation lookup runs only when ``VT_API_KEY`` is set;
without it, verdicts rest on the local heuristics alone and say so.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

# Order matters: index gives a comparable rank for "highest severity wins".
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Read at most this many bytes for the text-content heuristics. A malicious
# payload announces itself early; reading a whole large upload buys nothing.
_TEXT_SCAN_LIMIT = 512 * 1024

# The EICAR anti-malware test file. Detecting it is a real, unambiguous
# positive that lets a user verify the pipeline end to end.
_EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Extensions that execute or script on a double-click / open.
_DANGEROUS_EXT = {
    "exe", "scr", "com", "pif", "cpl", "msi", "msp", "bat", "cmd", "vbs",
    "vbe", "js", "jse", "wsf", "wsh", "ps1", "psm1", "hta", "jar", "lnk",
    "reg", "dll", "sh", "apk", "app", "gadget",
}
# Office formats that can carry macros.
_MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "xla"}
_ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "iso", "img", "cab", "ace"}

# Magic-byte signatures → a friendly type label.
_MAGIC = [
    (b"MZ", "Windows executable (PE)"),
    (b"\x7fELF", "Linux executable (ELF)"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP / Office (OOXML)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"\xd0\xcf\x11\xe0", "Legacy Office (OLE)"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"#!", "Script with shebang"),
]

# Suspicious in-file content patterns (case-insensitive), each with a reason.
_CONTENT_PATTERNS = [
    (rb"powershell.{0,40}-e(nc(odedcommand)?)?\b", "MEDIUM", "Encoded PowerShell command"),
    (rb"frombase64string", "MEDIUM", "Base64 decode call (common in droppers)"),
    (rb"(?:curl|wget)\b[^\n]{0,120}\|\s*(?:ba)?sh", "HIGH", "Remote script piped to a shell"),
    (rb"invoke-(?:expression|webrequest)|iex\s*\(", "MEDIUM", "PowerShell download/exec"),
    (rb"cmd(?:\.exe)?\s+/c", "LOW", "Shell command invocation"),
    (rb"eval\s*\(\s*(?:atob|unescape|base64)", "MEDIUM", "Obfuscated script eval"),
    (rb"document\.write\s*\(\s*unescape", "MEDIUM", "Classic drive-by obfuscation"),
    (rb"<script[^>]*>[^<]{0,40}eval", "MEDIUM", "Inline script with eval"),
    (rb"vbaproject\.bin", "MEDIUM", "Embedded VBA macro project"),
]

# Hosts that hide the real destination behind a redirect.
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly",
}
# TLDs disproportionately abused for malware and phishing.
_RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "gq", "ml", "cf", "ga", "work",
    "click", "link", "country", "kim", "loan", "download", "review",
}
# Query keys that only track the user; stripped in the sanitized URL.
_TRACKING_KEYS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "mc_eid", "mc_cid", "igshid", "ref", "ref_src",
    "yclid", "_hsenc", "_hsmi", "vero_id", "wickedid",
}
_SAFE_SCHEMES = {"http", "https"}


@dataclass
class _Indicator:
    severity: str
    title: str
    detail: str = ""


@dataclass
class _Result:
    kind: str
    name: str
    verdict: str = "clean"
    score: int = 0
    sha256: str | None = None
    size: int | None = None
    detected_type: str | None = None
    sanitized: str | None = None
    note: str = ""
    indicators: list[_Indicator] = field(default_factory=list)
    engines: dict = field(default_factory=dict)

    def add(self, severity: str, title: str, detail: str = "") -> None:
        self.indicators.append(_Indicator(severity, title, detail))


def _rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def _finalize(result: _Result) -> None:
    """Derive verdict and a 0-100 risk score from the collected indicators."""
    if not result.indicators:
        result.verdict = "clean"
        result.score = 0
        return

    top = max(result.indicators, key=lambda i: _rank(i.severity)).severity
    # Score: weighted by the worst finding, nudged up by the count of findings.
    base = {"INFO": 5, "LOW": 25, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 100}[top]
    result.score = min(100, base + max(0, len(result.indicators) - 1) * 3)

    if top == "CRITICAL":
        result.verdict = "malicious"
    elif top == "HIGH":
        result.verdict = "suspicious"
    elif top == "MEDIUM":
        result.verdict = "suspicious"
    elif top == "LOW":
        result.verdict = "low"
    else:
        result.verdict = "clean"


def _detect_type(data: bytes) -> str | None:
    head = data[:16]
    for sig, label in _MAGIC:
        if head.startswith(sig):
            return label
    # Printable-heavy content with no known magic reads as text.
    sample = data[:512]
    if sample and sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) / len(sample) > 0.9:
        return "Plain text"
    return None


def _ext(name: str) -> str:
    _, _, ext = name.rpartition(".")
    return ext.lower() if "." in name else ""


# --- File scanning ---------------------------------------------------------


def scan_file(filename: str, data: bytes, use_virustotal: bool = True) -> _Result:
    """Screen one uploaded file. ``data`` is the raw bytes."""
    result = _Result(kind="file", name=filename or "unnamed")
    result.size = len(data)
    digest = hashlib.sha256(data).hexdigest()
    result.sha256 = digest
    result.detected_type = _detect_type(data)

    if not data:
        result.note = "Empty file; nothing to analyze."
        _finalize(result)
        return result

    # 1. EICAR test signature — a definitive positive.
    if _EICAR in data:
        result.add("CRITICAL", "EICAR test signature",
                   "Standard anti-malware test file. Detected by hash-independent match.")

    ext = _ext(filename)
    lower_name = (filename or "").lower()

    # 2. Dangerous / scriptable extensions.
    if ext in _DANGEROUS_EXT:
        result.add("MEDIUM", f"Executable or script type (.{ext})",
                   "This file type runs code when opened.")
    if ext in _MACRO_EXT:
        result.add("MEDIUM", f"Macro-enabled Office file (.{ext})",
                   "Can carry auto-running macros.")
    if ext in _ARCHIVE_EXT:
        result.add("LOW", f"Archive (.{ext})",
                   "Contents are not unpacked or inspected here.")

    # 3. Double extension, e.g. invoice.pdf.exe.
    parts = lower_name.split(".")
    if len(parts) >= 3 and parts[-1] in _DANGEROUS_EXT and parts[-2] in {
        "pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip",
    }:
        result.add("HIGH", "Double extension disguise",
                   f"Named to look like .{parts[-2]} but is .{parts[-1]}.")

    # 4. Extension vs. real content mismatch for the obvious executable case.
    detected = result.detected_type or ""
    if detected.startswith(("Windows executable", "Linux executable")) and ext not in _DANGEROUS_EXT:
        result.add("HIGH", "Content/extension mismatch",
                   f"Bytes are an executable but the name ends in .{ext or '(none)'}.")

    # 5. Content heuristics on the leading bytes.
    blob = data[:_TEXT_SCAN_LIMIT].lower()
    for pattern, severity, title in _CONTENT_PATTERNS:
        if re.search(pattern, blob, re.IGNORECASE):
            result.add(severity, title, "Matched a known malicious content pattern.")

    # 6. Optional VirusTotal reputation by hash.
    vt_used = False
    if use_virustotal:
        vt = _virustotal_hash(digest)
        if vt is not None:
            vt_used = True
            result.engines["virustotal"] = vt
            malicious = vt.get("malicious", 0)
            if malicious > 0:
                result.add("CRITICAL", f"VirusTotal: {malicious} engines flagged this",
                           "Reputation lookup by SHA-256.")

    _finalize(result)
    result.note = _note(vt_used)
    return result


# --- Link scanning ---------------------------------------------------------


def scan_link(url: str, use_virustotal: bool = True) -> _Result:
    """Screen one URL. No request is made to the URL itself."""
    raw = (url or "").strip()
    result = _Result(kind="link", name=raw)

    if not raw:
        result.verdict = "error"
        result.note = "Empty URL."
        return result

    parsed = urllib.parse.urlsplit(raw)
    scheme = (parsed.scheme or "").lower()

    if not scheme:
        result.verdict = "error"
        result.note = "No scheme; not a valid absolute URL."
        return result

    if scheme not in _SAFE_SCHEMES:
        result.add("HIGH", f"Unsafe scheme ({scheme}:)",
                   "Only http and https are treated as navigable.")
        _finalize(result)
        result.note = _note(False)
        return result

    host = (parsed.hostname or "").lower()
    if not host:
        result.verdict = "error"
        result.note = "No host in URL."
        return result

    # Embedded credentials.
    if parsed.username or "@" in parsed.netloc:
        result.add("HIGH", "Embedded credentials",
                   "A user:pass@ prefix is a classic phishing disguise.")

    # IP-literal host.
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) or ":" in host:
        result.add("MEDIUM", "IP address instead of a domain",
                   "Legitimate sites almost always use a domain name.")

    # Punycode / homograph.
    if "xn--" in host:
        result.add("HIGH", "Punycode host (possible homograph)",
                   "Internationalized name that may mimic a known brand.")

    # Subdomain depth.
    labels = host.split(".")
    if len(labels) > 4:
        result.add("LOW", "Deeply nested subdomains",
                   f"{len(labels)} labels; often used to bury a real domain.")

    # URL shortener.
    if host in _SHORTENERS:
        result.add("MEDIUM", "URL shortener",
                   "Hides the real destination behind a redirect.")

    # Risky TLD.
    tld = labels[-1] if labels else ""
    if tld in _RISKY_TLDS:
        result.add("MEDIUM", f"High-risk TLD (.{tld})",
                   "This TLD is disproportionately abused.")

    # Non-standard port.
    if parsed.port and parsed.port not in (80, 443):
        result.add("LOW", f"Non-standard port ({parsed.port})")

    # Executable in the path.
    path_ext = _ext(parsed.path)
    if path_ext in _DANGEROUS_EXT:
        result.add("MEDIUM", f"Points to an executable (.{path_ext})",
                   "The link downloads a file that runs code.")

    # Tracking params → build a sanitized URL.
    result.sanitized = _sanitize_url(parsed)
    if result.sanitized != raw:
        result.add("INFO", "Tracking parameters removed",
                   "A cleaned link is provided below.")

    # Optional VirusTotal URL reputation.
    vt_used = False
    if use_virustotal:
        vt = _virustotal_url(raw)
        if vt is not None:
            vt_used = True
            result.engines["virustotal"] = vt
            malicious = vt.get("malicious", 0)
            if malicious > 0:
                result.add("CRITICAL", f"VirusTotal: {malicious} engines flagged this URL",
                           "Reputation lookup by URL.")

    _finalize(result)
    result.note = _note(vt_used)
    return result


def _sanitize_url(parsed: urllib.parse.SplitResult) -> str:
    """Return a cleaned URL: no credentials, no tracking params, lowered host."""
    host = (parsed.hostname or "").lower()
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"

    kept = [
        (k, v)
        for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if k.lower() not in _TRACKING_KEYS
    ]
    query = urllib.parse.urlencode(kept)
    return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path, query, ""))


def _note(vt_used: bool) -> str:
    base = ("Local heuristics: hash, type sniff, EICAR match, content and "
            "structure checks.")
    if vt_used:
        return base + " VirusTotal reputation consulted."
    return base + " No external reputation service consulted (set VT_API_KEY to enable)."


# --- VirusTotal (optional) -------------------------------------------------


def _vt_key() -> str:
    import os

    return os.environ.get("VT_API_KEY", "").strip()


def _vt_get(url: str) -> dict | None:
    key = _vt_key()
    if not key:
        return None
    try:
        req = urllib.request.Request(url, headers={"x-apikey": key})
        with urllib.request.urlopen(req, timeout=8) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        stats = (
            payload.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        if not stats:
            return None
        return {
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
        }
    except Exception:
        # A reputation lookup that fails is not a reason to fail the scan; the
        # local verdict already stands, and the note says VT was not consulted.
        return None


def _virustotal_hash(sha256: str) -> dict | None:
    return _vt_get(f"https://www.virustotal.com/api/v3/files/{sha256}")


def _virustotal_url(url: str) -> dict | None:
    import base64

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return _vt_get(f"https://www.virustotal.com/api/v3/urls/{url_id}")
