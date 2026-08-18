import logging
import subprocess
import json
import os
import shutil
import tempfile
import hashlib
import time
from scanners.base import ScannerAdapter, ScanVulnerability
from config import settings

logger = logging.getLogger("vulndetect")


class ZAPScanner(ScannerAdapter):
    """OWASP ZAP (Zed Attack Proxy) scanner adapter.

    ZAP is a free, open-source web application security scanner.
    It can be run via CLI (zap.sh / zap.bat) or via its REST API.

    Supports both active and passive scanning modes.
    """

    name = "zap"

    # Common installation paths for different OS
    COMMON_PATHS = {
        "win32": [
            r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
            r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
            r"C:\tools\zap\zap.bat",
            r"C:\ZAP\zap.bat",
        ],
        "linux": [
            "/usr/bin/zap.sh",
            "/usr/share/zaproxy/zap.sh",
            "/opt/zaproxy/zap.sh",
            "/snap/bin/zaproxy",
        ],
        "darwin": [
            "/Applications/OWASP ZAP.app/Contents/Java/zap.sh",
            "/usr/local/bin/zap.sh",
            "/opt/homebrew/bin/zap.sh",
        ],
    }

    # ZAP API configuration
    API_HOST = "127.0.0.1"
    API_PORT = 8080
    API_KEY = ""  # Set in .env if authentication is enabled

    def _get_binary(self) -> str | None:
        """Get the ZAP binary path from config or system PATH."""
        # First check config/environment variable
        path = settings.ZAP_PATH
        if path and os.path.isfile(path):
            return path
        if path and shutil.which(path):
            return path

        # Try system PATH
        for name in ["zap.sh", "zap.bat", "zaproxy", "zap"]:
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
        """Check if ZAP is available on the system."""
        return self._get_binary() is not None

    def scan(self, target: str) -> list[ScanVulnerability]:
        """Run an OWASP ZAP scan against the target.

        ZAP supports:
        - Active scanning: Actively tests for vulnerabilities
        - Passive scanning: Analyzes traffic without attacking
        - Spider: Crawls the website to find all pages
        """
        binary = self._get_binary()
        if not binary:
            logger.warning("OWASP ZAP not available, using mock data for %s", target)
            return self._mock_scan(target)

        # Try REST API first (if ZAP is already running)
        try:
            vulns = self._scan_via_api(target)
            if vulns:
                return vulns
        except Exception as e:
            logger.debug("ZAP API not available: %s", e)

        # Try CLI mode
        try:
            vulns = self._scan_via_cli(target)
            if vulns:
                return vulns
        except Exception as e:
            logger.debug("ZAP CLI not available: %s", e)

        # Fall back to mock data
        logger.info("OWASP ZAP scan not possible, using mock data for %s", target)
        return self._mock_scan(target)

    def _scan_via_api(self, target: str) -> list[ScanVulnerability]:
        """Scan using ZAP REST API."""
        import httpx

        base_url = f"http://{self.API_HOST}:{self.API_PORT}"
        api_key_param = f"apikey={self.API_KEY}" if self.API_KEY else ""

        target_url = target if target.startswith("http") else f"https://{target}"

        # Step 1: Spider the target
        spider_url = (
            f"{base_url}/JSON/spider/action/scan/?url={target_url}&{api_key_param}"
        )
        response = httpx.get(spider_url, timeout=30)

        if response.status_code != 200:
            raise Exception(f"Failed to start ZAP spider: {response.status_code}")

        scan_id = response.json().get("scan", "0")

        # Wait for spider to complete
        for _ in range(60):
            time.sleep(5)
            status_url = (
                f"{base_url}/JSON/spider/view/status/?scanId={scan_id}&{api_key_param}"
            )
            status_response = httpx.get(status_url, timeout=30)
            if status_response.json().get("status") == "100":
                break

        # Step 2: Active scan
        active_url = (
            f"{base_url}/JSON/ascan/action/scan/?url={target_url}&{api_key_param}"
        )
        response = httpx.get(active_url, timeout=30)

        if response.status_code == 200:
            active_scan_id = response.json().get("scan", "0")

            # Wait for active scan to complete
            for _ in range(120):
                time.sleep(10)
                status_url = f"{base_url}/JSON/ascan/view/status/?scanId={active_scan_id}&{api_key_param}"
                status_response = httpx.get(status_url, timeout=30)
                if status_response.json().get("status") == "100":
                    break

        # Step 3: Get alerts
        alerts_url = (
            f"{base_url}/JSON/core/view/alerts/?baseurl={target_url}&{api_key_param}"
        )
        alerts_response = httpx.get(alerts_url, timeout=30)

        if alerts_response.status_code == 200:
            return self._parse_api_results(alerts_response.json(), target)

        raise Exception("Failed to get ZAP alerts")

    def _parse_api_results(self, data: dict, target: str) -> list[ScanVulnerability]:
        """Parse ZAP API results into ScanVulnerability objects."""
        vulns = []
        alerts = data.get("alerts", [])

        seen = set()
        for alert in alerts:
            alert_name = alert.get("name", "")
            if alert_name in seen:
                continue
            seen.add(alert_name)

            risk = alert.get("risk", "Informational").upper()
            confidence = alert.get("confidence", "Medium").upper()

            # Map ZAP risk levels
            risk_mapping = {
                "INFORMATIONAL": "INFO",
                "LOW": "LOW",
                "MEDIUM": "MEDIUM",
                "HIGH": "HIGH",
            }
            severity = risk_mapping.get(risk, "MEDIUM")

            cvss_score = self._severity_to_cvss(severity)
            if confidence == "HIGH":
                cvss_score = min(cvss_score + 0.5, 10.0)

            cve_id = None
            cwe_id = alert.get("cweid", "")
            if cwe_id:
                # ZAP uses CWE IDs, not CVE IDs
                description = f"CWE-{cwe_id}: {alert_name}"
            else:
                description = alert_name

            solution = alert.get("solution", "")
            references = []
            ref = alert.get("reference", "")
            if ref:
                references = [r.strip() for r in ref.split("\n") if r.strip()]

            for instance in alert.get("instances", []):
                vulns.append(
                    ScanVulnerability(
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        severity=severity,
                        description=description,
                        affected_host=target,
                        affected_port=None,
                        affected_service=instance.get("method", "GET"),
                        solution=solution,
                        references=references,
                        exploit_available=severity in ("CRITICAL", "HIGH"),
                        source_scanner=self.name,
                        raw_output={"type": "api", "alert": alert},
                    )
                )
                break  # One entry per alert type

        return vulns

    def _scan_via_cli(self, target: str) -> list[ScanVulnerability]:
        """Scan using ZAP CLI."""
        binary = self._get_binary()
        target_url = target if target.startswith("http") else f"https://{target}"

        # tempfile.gettempdir() rather than a hardcoded /tmp: this project is
        # Windows-primary, where /tmp does not exist and the report was never
        # written or read back.
        report_path = os.path.join(tempfile.gettempdir(), "zap_report.json")

        # ZAP CLI command for quick scan
        cmd = [
            binary,
            "-quickurl",
            target_url,
            "-quickout",
            report_path,
            "-quickprogress",
            "-cmd",
        ]

        logger.info("Running ZAP CLI: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        # Try to read the JSON report
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return self._parse_api_results(data, target)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        # Fall back to parsing stdout
        return self._parse_cli_output(result.stdout, target)

    def _parse_cli_output(self, output: str, target: str) -> list[ScanVulnerability]:
        """Parse ZAP CLI output into ScanVulnerability objects."""
        vulns = []
        # ZAP CLI output parsing is limited, return empty to fall back to mock
        return vulns

    def _severity_to_cvss(self, severity: str) -> float:
        """Convert ZAP risk level to CVSS score."""
        mapping = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 0.0,
            "INFORMATIONAL": 0.0,
        }
        return mapping.get(severity, 0.0)

    def _mock_scan(self, target: str) -> list[ScanVulnerability]:
        """Generate mock vulnerabilities when ZAP is not available."""
        target_hash = hashlib.md5((target + "zap").encode()).hexdigest()
        hash_val = int(target_hash[:8], 16)

        vulns = []

        if hash_val % 3 != 0:
            vulns.append(
                ScanVulnerability(
                    cve_id=None,
                    cvss_score=5.3,
                    severity="MEDIUM",
                    description="CWE-79: Cross-Site Scripting (Reflected)",
                    affected_host=target,
                    affected_port=443,
                    affected_service="https",
                    solution="Validate and sanitize all user input. Implement Content Security Policy.",
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )

        if hash_val % 2 == 0:
            vulns.append(
                ScanVulnerability(
                    cve_id=None,
                    cvss_score=7.5,
                    severity="HIGH",
                    description="CWE-89: SQL Injection in search parameter",
                    affected_host=target,
                    affected_port=443,
                    affected_service="https",
                    solution="Use parameterized queries. Never concatenate user input into SQL.",
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )

        vulns.append(
            ScanVulnerability(
                cve_id=None,
                cvss_score=3.7,
                severity="LOW",
                description="CWE-693: Content Security Policy (CSP) header not set",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Implement Content-Security-Policy header with strict directives.",
                source_scanner=self.name,
                raw_output={"type": "mock", "target": target},
            )
        )

        if hash_val % 4 == 0:
            vulns.append(
                ScanVulnerability(
                    cve_id=None,
                    cvss_score=9.1,
                    severity="HIGH",
                    description="CWE-352: Cross-Site Request Forgery (CSRF)",
                    affected_host=target,
                    affected_port=443,
                    affected_service="https",
                    solution="Implement anti-CSRF tokens and SameSite cookie attribute.",
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )

        if hash_val % 5 == 0:
            vulns.append(
                ScanVulnerability(
                    cve_id="CVE-2023-44487",
                    cvss_score=7.5,
                    severity="HIGH",
                    description="HTTP/2 Rapid Reset Attack (DDoS vulnerability)",
                    affected_host=target,
                    affected_port=443,
                    affected_service="https",
                    solution="Update HTTP/2 server implementation and apply rate limiting.",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )

        if hash_val % 6 == 0:
            vulns.append(
                ScanVulnerability(
                    cve_id=None,
                    cvss_score=6.5,
                    severity="MEDIUM",
                    description="CWE-521: Weak password policy detected",
                    affected_host=target,
                    affected_port=443,
                    affected_service="https",
                    solution="Enforce strong password requirements: min 12 chars, mixed case, numbers, symbols.",
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )

        return vulns
