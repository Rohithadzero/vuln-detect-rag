"""OpenVAS / Greenbone Vulnerability Manager scanner adapter.

OpenVAS is the free, open-source enterprise vulnerability scanner. It is driven
through GMP (Greenbone Management Protocol), an XML protocol spoken over a TLS
socket or a local Unix socket, rather than a command-line tool that prints a
report.

A full scan is a multi-step conversation with the manager daemon:

    authenticate -> create target -> create task -> start task
                 -> poll until the task reports 100% -> fetch the report XML
                 -> parse results into ScanVulnerability

Running this requires a working GVM stack (the Greenbone community containers
are the least painful route) and a completed NVT feed sync, which takes tens of
minutes on first run. When the daemon is not reachable the adapter degrades to
clearly-labelled sample data rather than failing the scan.
"""

import logging
import os
import time

from scanners.base import ScannerAdapter, ScanVulnerability
from config import settings

logger = logging.getLogger("vulndetect")

#: Poll interval while a scan runs. OpenVAS scans are slow — minutes to hours —
#: so polling faster only adds load without returning results any sooner.
POLL_INTERVAL_SECONDS = 15


class OpenVASScanner(ScannerAdapter):
    name = "openvas"

    #: "Full and fast" — the default Greenbone scan config, and the only one
    #: guaranteed to exist on a fresh install.
    FULL_AND_FAST_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
    #: The default OpenVAS scanner UUID, likewise always present.
    DEFAULT_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"

    def __init__(self):
        self.host = os.getenv("GVM_HOST", "127.0.0.1")
        self.port = int(os.getenv("GVM_PORT", "9390"))
        self.socket_path = os.getenv("GVM_SOCKET_PATH", "")
        self.username = os.getenv("GVM_USERNAME", "admin")
        self.password = os.getenv("GVM_PASSWORD", "")
        # An OpenVAS scan can legitimately run for hours; this caps how long we
        # are willing to wait before giving up and returning what we have.
        self.timeout = int(os.getenv("GVM_SCAN_TIMEOUT", "3600"))

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Whether a GVM daemon is reachable and credentials are configured.

        Checked before every scan so the UI can distinguish "OpenVAS is set up"
        from "OpenVAS will return sample data".
        """
        if not self.password:
            logger.debug("GVM_PASSWORD not set; OpenVAS cannot authenticate")
            return False

        try:
            import gvm  # noqa: F401
        except ImportError:
            logger.debug("python-gvm not installed; OpenVAS unavailable")
            return False

        return self._daemon_reachable()

    def _daemon_reachable(self) -> bool:
        """Probe the GMP endpoint without performing a full handshake."""
        if self.socket_path:
            return os.path.exists(self.socket_path)

        import socket

        try:
            with socket.create_connection((self.host, self.port), timeout=5):
                return True
        except OSError as e:
            logger.debug("GVM not reachable at %s:%s (%s)", self.host, self.port, e)
            return False

    def _connect(self):
        """Open a GMP connection, preferring a local socket when configured."""
        from gvm.connections import TLSConnection, UnixSocketConnection
        from gvm.protocols.gmp import Gmp

        if self.socket_path:
            connection = UnixSocketConnection(path=self.socket_path)
        else:
            connection = TLSConnection(
                hostname=self.host, port=self.port, timeout=30
            )

        gmp = Gmp(connection=connection)
        gmp.determine_supported_gmp()
        return gmp

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan(self, target: str) -> list[ScanVulnerability]:
        """Run a real OpenVAS scan, falling back to sample data if unavailable."""
        if not self.is_available():
            logger.warning(
                "OpenVAS/GVM not available (set GVM_HOST, GVM_USERNAME, "
                "GVM_PASSWORD and install python-gvm). Using sample data for %s",
                target,
            )
            return self._mock_scan(target)

        target_id = task_id = None
        gmp = None

        try:
            gmp = self._connect()
            with gmp:
                gmp.authenticate(self.username, self.password)
                logger.info("Authenticated to GVM at %s", self.host)

                # Names are timestamped because GMP rejects duplicates, and a
                # re-scan of the same host is a normal thing to do.
                stamp = int(time.time())
                target_id = self._create_target(gmp, target, stamp)
                task_id = self._create_task(gmp, target, target_id, stamp)

                gmp.start_task(task_id)
                logger.info("Started OpenVAS task %s against %s", task_id, target)

                report_id = self._await_completion(gmp, task_id)
                if not report_id:
                    logger.error("OpenVAS scan did not complete for %s", target)
                    return self._mock_scan(target)

                report_xml = gmp.get_report(
                    report_id, details=True, ignore_pagination=True
                )
                return self._parse_report(report_xml, target)

        except Exception:
            logger.exception("OpenVAS scan failed for %s", target)
            return self._mock_scan(target)

        finally:
            # Targets and tasks accumulate in the GVM database otherwise, and a
            # target cannot be deleted while a task still references it.
            if gmp is not None:
                self._cleanup(gmp, task_id, target_id)

    def _create_target(self, gmp, target: str, stamp: int) -> str:
        """Create a GMP target object and return its ID."""
        response = gmp.create_target(
            name=f"VulnDetectRAG {target} {stamp}",
            hosts=[target],
            port_range="T:1-65535,U:1-1024",
        )
        return response.get("id")

    def _create_task(self, gmp, target: str, target_id: str, stamp: int) -> str:
        """Create a scan task bound to a target and return its ID."""
        config_id = os.getenv("GVM_SCAN_CONFIG", self.FULL_AND_FAST_CONFIG)
        scanner_id = os.getenv("GVM_SCANNER_ID", self.DEFAULT_SCANNER)

        response = gmp.create_task(
            name=f"VulnDetectRAG scan {target} {stamp}",
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id,
        )
        return response.get("id")

    def _await_completion(self, gmp, task_id: str) -> str | None:
        """Poll until the task finishes, returning its report ID."""
        deadline = time.time() + self.timeout
        last_progress = -1

        while time.time() < deadline:
            task = gmp.get_task(task_id)
            status = task.find(".//status")
            progress = task.find(".//progress")

            status_text = status.text if status is not None else "Unknown"
            try:
                progress_value = int(progress.text) if progress is not None else 0
            except (TypeError, ValueError):
                progress_value = 0

            if progress_value != last_progress:
                logger.info("OpenVAS task %s: %s (%d%%)",
                            task_id, status_text, progress_value)
                last_progress = progress_value

            if status_text in ("Done", "Stopped"):
                report = task.find(".//last_report/report")
                return report.get("id") if report is not None else None

            if status_text in ("Interrupted", "Failed"):
                logger.error("OpenVAS task %s ended as %s", task_id, status_text)
                return None

            time.sleep(POLL_INTERVAL_SECONDS)

        logger.error("OpenVAS task %s exceeded the %ds budget", task_id, self.timeout)
        return None

    def _parse_report(self, report_xml, target: str) -> list[ScanVulnerability]:
        """Convert a GMP report into normalized findings.

        GMP reports one <result> per finding, carrying a threat level, a CVSS
        base score, and NVT metadata that usually includes the CVE references.
        """
        vulns: list[ScanVulnerability] = []
        seen: set = set()

        for result in report_xml.findall(".//result"):
            name = self._text(result, "name")
            host = self._text(result, "host") or target
            port_text = self._text(result, "port")
            threat = (self._text(result, "threat") or "Log").upper()
            description = self._text(result, "description")

            nvt = result.find("nvt")
            cvss_score = 0.0
            solution = ""
            references: list[str] = []
            cve_ids: list[str] = []

            if nvt is not None:
                try:
                    cvss_score = float(self._text(nvt, "cvss_base") or 0.0)
                except (TypeError, ValueError):
                    cvss_score = 0.0

                solution = self._text(nvt, "solution")
                summary = self._text(nvt, "summary")
                if summary and not description:
                    description = summary

                # CVEs appear either in <refs> or in the legacy <cve> element.
                for ref in nvt.findall(".//ref"):
                    ref_id = ref.get("id", "")
                    ref_type = (ref.get("type") or "").lower()
                    if ref_type == "cve" and ref_id.upper().startswith("CVE-"):
                        cve_ids.append(ref_id.upper())
                    elif ref_id.startswith("http"):
                        references.append(ref_id)

                legacy_cve = self._text(nvt, "cve")
                if legacy_cve:
                    cve_ids.extend(self.extract_cves(legacy_cve))

            # "Log" findings are informational noise, not vulnerabilities.
            if threat == "LOG" and not cve_ids:
                continue

            port_number = self._parse_port(port_text)
            service = port_text.split("/")[-1] if "/" in (port_text or "") else None

            primary_cve = cve_ids[0] if cve_ids else None
            dedup_key = f"{primary_cve or name}:{host}:{port_number}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            severity = (
                self.parse_severity(cvss_score) if cvss_score > 0
                else self._threat_to_severity(threat)
            )

            vulns.append(
                ScanVulnerability(
                    cve_id=primary_cve,
                    cvss_score=cvss_score,
                    severity=severity,
                    description=(description or name or "Unnamed finding")[:2000],
                    affected_host=host,
                    affected_port=port_number,
                    affected_service=service,
                    solution=solution,
                    references=references[:10],
                    exploit_available=bool(cve_ids) and cvss_score >= 7.0,
                    source_scanner=self.name,
                    raw_output={
                        "type": "gmp",
                        "nvt_name": name,
                        "threat": threat,
                        "all_cves": cve_ids,
                    },
                )
            )

        logger.info("OpenVAS returned %d findings for %s", len(vulns), target)
        return vulns

    @staticmethod
    def _text(element, tag: str) -> str:
        """Text content of a child element, or an empty string."""
        if element is None:
            return ""
        child = element.find(tag)
        return (child.text or "").strip() if child is not None else ""

    @staticmethod
    def _parse_port(port_text: str) -> int | None:
        """Extract the numeric port from GMP's '443/tcp' style value."""
        if not port_text:
            return None
        head = port_text.split("/")[0].strip()
        try:
            return int(head)
        except ValueError:
            return None

    @staticmethod
    def _threat_to_severity(threat: str) -> str:
        """Map a GMP threat level onto our severity vocabulary."""
        return {
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "LOG": "INFO",
            "DEBUG": "INFO",
        }.get(threat.upper(), "LOW")

    def _cleanup(self, gmp, task_id: str | None, target_id: str | None) -> None:
        """Remove the task and target created for this scan."""
        try:
            if task_id:
                gmp.delete_task(task_id, ultimate=True)
            if target_id:
                gmp.delete_target(target_id, ultimate=True)
        except Exception:
            # Cleanup failure is not worth failing a completed scan over.
            logger.debug("Could not clean up GVM task/target", exc_info=True)

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------

    def _mock_scan(self, target: str) -> list[ScanVulnerability]:
        """Sample data used when no GVM daemon is reachable.

        Every entry is tagged type="mock" so the API, the UI and the RAG
        assistant can all label it as simulated rather than observed.
        """
        return [
            ScanVulnerability(
                cve_id="CVE-2023-36884",
                cvss_score=8.3,
                severity="HIGH",
                description="Microsoft Office and Windows HTML RCE Vulnerability",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Apply Microsoft July 2023 security updates",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-36884"],
                source_scanner=self.name,
                raw_output={"type": "mock"},
            ),
            ScanVulnerability(
                cve_id="CVE-2022-47966",
                cvss_score=9.8,
                severity="CRITICAL",
                description="Zoho ManageEngine RCE via Apache Santuario",
                affected_host=target,
                affected_port=8443,
                affected_service="https",
                solution="Update ManageEngine products to latest versions",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-47966"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"},
            ),
            ScanVulnerability(
                cve_id="CVE-2023-20198",
                cvss_score=10.0,
                severity="CRITICAL",
                description="Cisco IOS XE Web UI Privilege Escalation",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Disable HTTP server on Cisco IOS XE, apply patches",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-20198"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"},
            ),
            ScanVulnerability(
                cve_id="CVE-2023-22515",
                cvss_score=10.0,
                severity="CRITICAL",
                description="Confluence Data Center and Server Broken Access Control",
                affected_host=target,
                affected_port=8090,
                affected_service="http",
                solution="Upgrade Confluence to fixed versions",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-22515"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"},
            ),
        ]
