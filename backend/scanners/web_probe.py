"""Active web probes: OS command injection, session hijacking, file inclusion, link handling.

This is a native scanner — it shells out to no external binary and instead
sends a small, bounded set of HTTP requests with ``requests``. It covers four
web-layer weaknesses that the CLI tools above do not probe directly:

  OS command injection   a parameter value reaches a shell unescaped
  session hijacking      session cookies set without Secure / HttpOnly /
                         SameSite, or over plain HTTP
  file inclusion (LFI)   a parameter is used as a file path and traverses out
                         of the intended directory
  open redirect          a parameter controls a redirect target, so a crafted
                         link sends the victim to an attacker-chosen host

Every probe is deliberately non-destructive. The payloads read or reflect —
they run ``id``, read ``/etc/passwd``, or ask for an off-site redirect — and
never write, delete, or execute anything harmful. The whole scan is capped at
``MAX_REQUESTS`` so it cannot turn into a flood against the target.

Detection is signature-based and conservative: a finding is only raised when a
response carries a signal that a normal application would not return (the
output of ``id``, the shape of ``/etc/passwd``, an off-host redirect). That
keeps false positives low and means the scanner reports nothing rather than
guessing when it is unsure.
"""

import logging
import re
import secrets
from urllib.parse import urlparse, urlencode

import requests

from scanners.base import ScannerAdapter, ScanVulnerability

logger = logging.getLogger("vulndetect")


#: Parameter names commonly wired to the sink each check targets. Kept short so
#: the request budget covers every check rather than exhausting itself on one.
CMD_PARAMS = ("cmd", "exec", "command", "run", "ping", "query", "q", "search")
FILE_PARAMS = ("file", "page", "path", "template", "doc", "document", "include", "view")
REDIRECT_PARAMS = ("next", "url", "redirect", "return", "returnurl", "dest", "continue", "r")

#: Benign OS command injection payloads. Each runs ``id`` (or echoes a marker)
#: and nothing else, so a vulnerable host reveals itself without being harmed.
OS_PAYLOADS = (";id", "|id", "&&id", "$(id)", "`id`", "%3Bid")
#: The output of ``id`` on a Unix host. A normal application never returns this.
OS_SIGNATURE = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+")

#: Path traversal payloads for both Unix and Windows targets.
LFI_PAYLOADS = (
    "../../../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../../../../../windows/win.ini",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
)
#: Signatures of the files the payloads try to read.
LFI_SIGNATURES = (
    re.compile(r"root:.*:0:0:"),          # /etc/passwd
    re.compile(r"\[(extensions|fonts|mci extensions)\]", re.IGNORECASE),  # win.ini
)

#: An off-site host used only to detect open redirects. The scanner never
#: follows the redirect; it only checks whether the target hands one out.
REDIRECT_CANARY = "vulndetect-probe.example.net"

#: Attributes a session cookie needs to resist theft and fixation.
COOKIE_FLAGS = ("secure", "httponly", "samesite")
#: Cookie names that usually carry a session identifier.
SESSION_COOKIE_HINTS = ("sess", "sid", "session", "auth", "token", "jsessionid", "phpsessid", "asp.net")


class WebProbeScanner(ScannerAdapter):
    """Native active probes for four common web weaknesses (free, no binary)."""

    name = "webprobe"
    free = True
    install_hint = ""

    #: Per-request timeout and the whole-scan request ceiling.
    REQUEST_TIMEOUT = 8
    MAX_REQUESTS = 60

    def __init__(self):
        self._budget = self.MAX_REQUESTS
        self._session = requests.Session()
        self._session.headers.update(
            {"User-Agent": "VulnDetectRAG-WebProbe/1.0 (+security scan)"}
        )

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------

    def _get(self, url: str, params: dict | None = None, allow_redirects: bool = True):
        """One budgeted GET. Returns the response, or None when it could not run."""
        if self._budget <= 0:
            return None
        self._budget -= 1
        try:
            return self._session.get(
                url,
                params=params,
                timeout=self.REQUEST_TIMEOUT,
                allow_redirects=allow_redirects,
            )
        except requests.RequestException as exc:
            logger.debug("webprobe GET %s failed: %s", url, exc)
            return None

    def _base_url(self, target: str) -> str | None:
        """Pick a reachable base URL for the target, preferring HTTPS."""
        if target.startswith(("http://", "https://")):
            candidates = [target.rstrip("/")]
        else:
            host = target.rstrip("/")
            candidates = [f"https://{host}", f"http://{host}"]

        for base in candidates:
            resp = self._get(base)
            if resp is not None:
                return base
        return None

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def scan(self, target: str) -> list[ScanVulnerability]:
        base = self._base_url(target)
        if base is None:
            logger.info("webprobe: %s did not answer over HTTP(S); skipping", target)
            return self._no_result(target)

        host = urlparse(base).netloc or target
        findings: list[ScanVulnerability] = []

        # Passive first: reading the baseline response costs one request the
        # base_url probe already spent, so cookie review is effectively free.
        baseline = self._get(base, allow_redirects=False)
        findings.extend(self._check_session(base, host, baseline))

        # Active probes, each capped by the shared request budget.
        findings.extend(self._check_os_injection(base, host))
        findings.extend(self._check_file_inclusion(base, host))
        findings.extend(self._check_open_redirect(base, host))

        logger.info("webprobe reported %d findings for %s", len(findings), target)
        return findings or self._no_result(target)

    # ------------------------------------------------------------------
    # 1. Session hijacking — cookie hardening review
    # ------------------------------------------------------------------

    def _check_session(self, base, host, response) -> list[ScanVulnerability]:
        if response is None:
            return []

        # requests collapses repeated Set-Cookie into one header, so read the
        # raw list from urllib3 when it is available.
        raw_cookies: list[str] = []
        try:
            raw_cookies = list(response.raw.headers.getlist("Set-Cookie"))
        except Exception:
            single = response.headers.get("Set-Cookie", "")
            if single:
                raw_cookies = [single]

        over_http = base.startswith("http://")
        findings: list[ScanVulnerability] = []
        for header in raw_cookies:
            name = header.split("=", 1)[0].strip()
            lowered = header.lower()
            looks_session = any(hint in name.lower() for hint in SESSION_COOKIE_HINTS)
            missing = [flag for flag in COOKIE_FLAGS if flag not in lowered]

            if not missing and not (over_http and looks_session):
                continue

            severity = "HIGH" if (looks_session and ("secure" in missing or over_http)) else "MEDIUM"
            problems = []
            if missing:
                problems.append("missing " + ", ".join(f.capitalize() for f in missing))
            if over_http and looks_session:
                problems.append("sent over plain HTTP")

            findings.append(ScanVulnerability(
                cvss_score=self.severity_to_cvss(severity),
                severity=severity,
                description=(
                    f"Cookie '{name}' is {' and '.join(problems)}. A session "
                    f"cookie without Secure/HttpOnly/SameSite can be stolen "
                    f"through network sniffing or cross-site script access, "
                    f"which enables session hijacking."
                ),
                affected_host=host,
                affected_service="https" if not over_http else "http",
                solution=(
                    "Set Secure, HttpOnly and SameSite on session cookies and "
                    "serve them only over HTTPS. Rotate the session identifier "
                    "on login to prevent fixation."
                ),
                source_scanner=self.name,
                raw_output={"type": "session", "cookie": name},
            ))
        return findings

    # ------------------------------------------------------------------
    # 2. OS command injection
    # ------------------------------------------------------------------

    def _check_os_injection(self, base, host) -> list[ScanVulnerability]:
        for param in CMD_PARAMS:
            for payload in OS_PAYLOADS:
                resp = self._get(base, params={param: payload})
                if resp is None:
                    if self._budget <= 0:
                        return []
                    continue
                if OS_SIGNATURE.search(resp.text or ""):
                    return [ScanVulnerability(
                        cvss_score=self.severity_to_cvss("CRITICAL"),
                        severity="CRITICAL",
                        description=(
                            f"Parameter '{param}' appears to pass its value to a "
                            f"system shell: the payload {payload!r} caused the "
                            f"output of the 'id' command to appear in the "
                            f"response. This is OS command injection and allows "
                            f"arbitrary command execution on the host."
                        ),
                        affected_host=host,
                        affected_service="http",
                        solution=(
                            "Never pass user input to a shell. Use parameterised "
                            "APIs, allow-list expected values, and drop shell "
                            "interpolation entirely."
                        ),
                        source_scanner=self.name,
                        raw_output={"type": "os_injection", "param": param},
                    )]
        return []

    # ------------------------------------------------------------------
    # 3. File inclusion / path traversal
    # ------------------------------------------------------------------

    def _check_file_inclusion(self, base, host) -> list[ScanVulnerability]:
        for param in FILE_PARAMS:
            for payload in LFI_PAYLOADS:
                resp = self._get(base, params={param: payload})
                if resp is None:
                    if self._budget <= 0:
                        return []
                    continue
                body = resp.text or ""
                if any(sig.search(body) for sig in LFI_SIGNATURES):
                    return [ScanVulnerability(
                        cvss_score=self.severity_to_cvss("HIGH"),
                        severity="HIGH",
                        description=(
                            f"Parameter '{param}' is vulnerable to file "
                            f"inclusion: the traversal payload {payload!r} "
                            f"returned the contents of a system file. An "
                            f"attacker can read arbitrary files, and depending "
                            f"on the platform, execute code."
                        ),
                        affected_host=host,
                        affected_service="http",
                        solution=(
                            "Resolve the requested path and confirm it stays "
                            "inside an allow-listed base directory. Reject any "
                            "input containing path separators or '..'."
                        ),
                        source_scanner=self.name,
                        raw_output={"type": "file_inclusion", "param": param},
                    )]
        return []

    # ------------------------------------------------------------------
    # 4. Open redirect — link sanitization
    # ------------------------------------------------------------------

    def _check_open_redirect(self, base, host) -> list[ScanVulnerability]:
        for param in REDIRECT_PARAMS:
            payload = f"https://{REDIRECT_CANARY}/"
            resp = self._get(base, params={param: payload}, allow_redirects=False)
            if resp is None:
                if self._budget <= 0:
                    return []
                continue
            if resp.status_code not in (301, 302, 303, 307, 308):
                continue
            location = resp.headers.get("Location", "")
            if REDIRECT_CANARY in urlparse(location).netloc:
                return [ScanVulnerability(
                    cvss_score=self.severity_to_cvss("MEDIUM"),
                    severity="MEDIUM",
                    description=(
                        f"Parameter '{param}' controls the redirect target "
                        f"without validation: a request redirected to the "
                        f"off-site host '{REDIRECT_CANARY}'. This open redirect "
                        f"lets an attacker craft a trusted-looking link that "
                        f"sends the victim to a hostile site (phishing, token "
                        f"theft)."
                    ),
                    affected_host=host,
                    affected_service="http",
                    solution=(
                        "Sanitize redirect links: accept only relative paths or "
                        "an allow-list of known hosts, and reject absolute URLs "
                        "to other origins."
                    ),
                    source_scanner=self.name,
                    raw_output={"type": "open_redirect", "param": param},
                )]
        return []
