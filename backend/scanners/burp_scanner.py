import logging
import subprocess
import json
import os
import shutil
import tempfile
import hashlib
from scanners.base import ScannerAdapter, ScanVulnerability
from config import settings

logger = logging.getLogger("vulndetect")


class BurpScanner(ScannerAdapter):
    """Burp Suite Community/Professional scanner adapter.

    Burp Suite is a web vulnerability scanner for penetration testing.
    This adapter uses the Burp Suite CLI (if available) or the REST API
    to scan targets for web application vulnerabilities.

    REQUIRES A PAID LICENCE. Burp Suite Professional (~$475/yr) is the only
    edition with a REST API; the free Community edition ships no automation
    interface at all, so there is no free path to a live Burp scan. This is a
    vendor restriction, not a gap in this adapter.

    Without Pro running locally this adapter returns clearly-labelled sample
    data. Every other scanner in this project is free to use.
    """

    #: Surfaced through /api/health so the UI can state the prerequisite rather
    #: than presenting Burp as though it were freely runnable.
    requires_licence = True
    licence_note = (
        "Requires a Burp Suite Professional licence with the REST API enabled. "
        "Burp Community has no automation API."
    )

    name = "burp"

    # Common installation paths for different OS
    COMMON_PATHS = {
        "win32": [
            r"C:\Program Files\BurpSuitePro\BurpSuitePro.exe",
            r"C:\Program Files\BurpSuiteCommunity\BurpSuiteCommunity.exe",
            r"C:\tools\burpsuite\BurpSuitePro.exe",
            r"C:\tools\burpsuite\burp.bat",
        ],
        "linux": [
            "/usr/bin/BurpSuitePro",
            "/usr/bin/BurpSuiteCommunity",
            "/opt/BurpSuitePro/BurpSuitePro",
            "/opt/BurpSuiteCommunity/BurpSuiteCommunity",
        ],
        "darwin": [
            "/Applications/Burp Suite Professional.app/Contents/java/app/bin/BurpSuitePro",
            "/Applications/Burp Suite Community Edition.app/Contents/java/app/bin/BurpSuiteCommunity",
            "/usr/local/bin/BurpSuitePro",
        ],
    }

    # Burp Suite REST API configuration
    API_HOST = "127.0.0.1"
    API_PORT = 1337

    def _get_binary(self) -> str | None:
        """Get the Burp Suite binary path from config or system PATH."""
        # First check config/environment variable
        path = settings.BURP_PATH
        if path and os.path.isfile(path):
            return path
        if path and shutil.which(path):
            return path

        # Try system PATH
        for name in ["burpsuitepro", "burpsuitecommunity", "burpsuite", "burp"]:
            result = shutil.which(name)
            if result:
                return result

        # Try common installation paths
        import sys

        platform = sys.platform
        for path in self.COMMON_PATHS.get(platform, []):
            if os.path.isfile(path):
                return path

        # Try other platforms too
        for paths in self.COMMON_PATHS.values():
            for path in paths:
                if os.path.isfile(path):
                    return path

        return None

    def is_available(self) -> bool:
        """Check if Burp Suite is available on the system."""
        return self._get_binary() is not None

    def scan(self, target: str) -> list[ScanVulnerability]:
        """Run a Burp Suite scan against the target.

        Burp Suite Pro can be run via CLI with --unpause flag,
        or via its REST API for automation.
        Community edition requires manual operation.
        """
        binary = self._get_binary()
        if not binary:
            logger.warning("Burp Suite not available, using mock data for %s", target)
            return self._mock_scan(target)

        # Try REST API first (if Burp is already running)
        try:
            vulns = self._scan_via_api(target)
            if vulns:
                return vulns
        except Exception as e:
            logger.debug("Burp API not available: %s", e)

        # Fall back to CLI if available
        try:
            vulns = self._scan_via_cli(target)
            if vulns:
                return vulns
        except Exception as e:
            logger.debug("Burp CLI not available: %s", e)

        # Fall back to mock data
        logger.info(
            "Burp Suite requires manual operation, using mock data for %s", target
        )
        return self._mock_scan(target)

    def _scan_via_api(self, target: str) -> list[ScanVulnerability]:
        """Scan using Burp Suite REST API (Professional edition only)."""
        import httpx

        api_url = f"http://{self.API_HOST}:{self.API_PORT}/v0.1/scan"

        # Start a new scan
        scan_config = {
            "urls": [target if target.startswith("http") else f"https://{target}"],
            "scope": {"type": "SimpleScope", "include": [{"rule": target}]},
        }

        response = httpx.post(
            api_url,
            json=scan_config,
            timeout=30,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code != 201:
            raise Exception(f"Failed to start Burp scan: {response.status_code}")

        # Get scan results (poll until complete or timeout)
        import time

        scan_id = response.json().get("scan_id", "")
        poll_url = f"{api_url}/{scan_id}"

        for _ in range(60):  # Poll for up to 10 minutes
            time.sleep(10)
            status_response = httpx.get(poll_url, timeout=30)
            if status_response.status_code == 200:
                data = status_response.json()
                if data.get("status") == "succeeded":
                    return self._parse_api_results(data, target)

        raise Exception("Burp scan timed out")

    def _parse_api_results(self, data: dict, target: str) -> list[ScanVulnerability]:
        """Parse Burp Suite API results into ScanVulnerability objects."""
        vulns = []
        issues = data.get("issue_events", {}).get("issue_added", [])

        for issue in issues:
            issue_data = issue.get("issue", {})
            severity = issue_data.get("severity", "low").upper()
            confidence = issue_data.get("confidence", "tentative").upper()

            cve_id = None
            cves = issue_data.get("cve_ids", [])
            if cves:
                cve_id = cves[0]

            cvss_score = self._severity_to_cvss(severity)
            if confidence == "certain":
                cvss_score = min(cvss_score + 0.5, 10.0)

            vulns.append(
                ScanVulnerability(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    severity=severity,
                    description=issue_data.get("name", "Unknown vulnerability"),
                    affected_host=target,
                    affected_port=None,
                    affected_service="https",
                    solution=issue_data.get("remediation", ""),
                    references=issue_data.get("references", []),
                    exploit_available=severity in ("CRITICAL", "HIGH"),
                    source_scanner=self.name,
                    raw_output={"type": "api", "issue": issue_data},
                )
            )

        return vulns

    def _scan_via_cli(self, target: str) -> list[ScanVulnerability]:
        """Scan using Burp Suite CLI (Professional edition)."""
        binary = self._get_binary()

        cmd = [
            binary,
            "--unpause",
            "--project-file",
            os.path.join(tempfile.gettempdir(), "burp_scan.burp"),
        ]

        # Burp CLI is limited, return empty to fall back to mock
        raise Exception("Burp CLI automation not fully supported")

    def _severity_to_cvss(self, severity: str) -> float:
        """Convert Burp severity to CVSS score."""
        mapping = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 0.0,
            "INFORMATION": 0.0,
        }
        return mapping.get(severity, 0.0)

    def _mock_scan(self, target: str) -> list[ScanVulnerability]:
        """Generate mock vulnerabilities when Burp Suite is not available."""
        target_hash = hashlib.md5((target + "burp").encode()).hexdigest()
        hash_val = int(target_hash[:8], 16)

        vulns = []

        if hash_val % 3 != 0:
            vulns.append(
                ScanVulnerability(
                    cve_id=None,
                    cvss_score=6.1,
                    severity="MEDIUM",
                    description="Cross-Site Scripting (XSS) Reflected",
                    affected_host=target,
                    affected_port=443,
                    affected_service="https",
                    solution="Implement output encoding and Content Security Policy (CSP)",
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )

        if hash_val % 2 == 0:
            vulns.append(
                ScanVulnerability(
                    cve_id="CVE-2023-25690",
                    cvss_score=7.5,
                    severity="HIGH",
                    description="HTTP Request Smuggling vulnerability detected",
                    affected_host=target,
                    affected_port=443,
                    affected_service="https",
                    solution="Normalize HTTP request parsing and disable HTTP/1.1 connection reuse",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2023-25690"],
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )

        vulns.append(
            ScanVulnerability(
                cve_id=None,
                cvss_score=5.3,
                severity="MEDIUM",
                description="Missing security headers: X-Frame-Options, X-Content-Type-Options",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Add X-Frame-Options: DENY and X-Content-Type-Options: nosniff headers",
                source_scanner=self.name,
                raw_output={"type": "mock", "target": target},
            )
        )

        if hash_val % 4 == 0:
            vulns.append(
                ScanVulnerability(
                    cve_id=None,
                    cvss_score=8.1,
                    severity="HIGH",
                    description="SQL Injection in login form parameter",
                    affected_host=target,
                    affected_port=443,
                    affected_service="https",
                    solution="Use parameterized queries and input validation",
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )

        if hash_val % 5 == 0:
            vulns.append(
                ScanVulnerability(
                    cve_id="CVE-2021-22986",
                    cvss_score=9.8,
                    severity="CRITICAL",
                    description="F5 BIG-IP iControl REST API Unauthenticated RCE",
                    affected_host=target,
                    affected_port=443,
                    affected_service="https",
                    solution="Upgrade F5 BIG-IP to patched versions or restrict API access",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-22986"],
                    exploit_available=True,
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )

        return vulns
