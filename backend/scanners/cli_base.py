"""Shared plumbing for scanners that shell out to a command-line tool.

Every CLI-backed adapter repeats the same three chores: find the binary across
three operating systems, run it safely with a timeout, and turn its JSON into
ScanVulnerability objects. Factoring that out keeps each adapter to the part
that is actually specific to its tool — the command line it builds and the
shape of the output it parses.

Target validation lives here too. Every subclass passes a user-supplied target
to a subprocess, so validating in one place is what stops that becoming a
command-injection surface repeated six times over.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

from scanners.base import ScannerAdapter, ScanVulnerability

logger = logging.getLogger("vulndetect")

#: Hostnames, IPv4 addresses and bare domains. Deliberately strict: anything
#: outside this set is rejected rather than escaped, because a target reaches
#: argv directly.
SAFE_TARGET = re.compile(r"^[a-zA-Z0-9._-]+$")

#: Also allow a URL form for the web scanners, still without shell metacharacters.
SAFE_URL = re.compile(r"^https?://[a-zA-Z0-9._\-/:]+$")


class CLIScannerAdapter(ScannerAdapter):
    """Base class for adapters that invoke an external binary."""

    #: Executable names to look for on PATH, in preference order.
    BINARY_NAMES: tuple = ()

    #: Per-platform fallback install locations, checked when PATH misses.
    COMMON_PATHS: Dict[str, List[str]] = {}

    #: Environment variable that can pin an explicit binary path.
    PATH_ENV_VAR: str = ""

    #: Seconds before the scan is abandoned.
    TIMEOUT: int = 600

    #: Whether this tool is free to use. Surfaced so the UI never presents a
    #: paid tool as freely available.
    free: bool = True

    #: Human-readable install hint, shown when the binary is missing.
    install_hint: str = ""

    # ------------------------------------------------------------------
    # Binary discovery
    # ------------------------------------------------------------------

    def _get_binary(self) -> Optional[str]:
        """Locate the tool's executable, or None if it is not installed."""
        configured = os.getenv(self.PATH_ENV_VAR, "") if self.PATH_ENV_VAR else ""
        if configured:
            if os.path.isfile(configured):
                return configured
            resolved = shutil.which(configured)
            if resolved:
                return resolved

        for name in self.BINARY_NAMES:
            resolved = shutil.which(name)
            if resolved:
                return resolved

        for path in self.COMMON_PATHS.get(sys.platform, []):
            if os.path.isfile(path):
                return path

        # Some tools are installed in a location this list does not know about
        # on another platform; check every candidate before giving up.
        for paths in self.COMMON_PATHS.values():
            for path in paths:
                if os.path.isfile(path):
                    return path

        return None

    def is_available(self) -> bool:
        """Whether the tool can actually run."""
        return self._get_binary() is not None

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    @staticmethod
    def validate_target(target: str, allow_url: bool = False) -> bool:
        """Whether a target is safe to place on a command line."""
        if not target:
            return False
        if SAFE_TARGET.match(target):
            return True
        return bool(allow_url and SAFE_URL.match(target))

    def run(self, cmd: List[str], timeout: Optional[int] = None) -> Optional[subprocess.CompletedProcess]:
        """Execute the tool, returning None when it could not be run.

        Never uses shell=True: arguments are passed as a list so a target
        containing shell metacharacters cannot be interpreted as a command.
        """
        logger.info("Running %s: %s", self.name, " ".join(cmd))
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.TIMEOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired:
            logger.error("%s timed out after %ds", self.name, timeout or self.TIMEOUT)
        except OSError as e:
            logger.error("Could not execute %s: %s", self.name, e)
        return None

    @staticmethod
    def parse_json(output: str) -> Optional[Any]:
        """Parse a tool's JSON output, tolerating leading banner text.

        Several tools print a version banner before their JSON, which makes a
        plain json.loads fail on otherwise valid output.
        """
        if not output:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            pass

        for opener, closer in (("{", "}"), ("[", "]")):
            start = output.find(opener)
            end = output.rfind(closer)
            if start != -1 and end > start:
                try:
                    return json.loads(output[start:end + 1])
                except json.JSONDecodeError:
                    continue

        logger.warning("%s produced output that is not valid JSON", "parse_json")
        return None

    @staticmethod
    def parse_jsonl(output: str) -> List[Any]:
        """Parse newline-delimited JSON, skipping malformed lines."""
        records = []
        for line in (output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    @staticmethod
    def severity_to_cvss(severity: str) -> float:
        """Approximate CVSS for tools that report only a severity band.

        These are midpoints of each band, used only when the tool gives no
        score of its own; a real score always takes precedence.
        """
        return {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 0.0,
            "INFORMATIONAL": 0.0,
            "NEGLIGIBLE": 0.0,
            "UNKNOWN": 0.0,
        }.get((severity or "").upper(), 0.0)

    def unavailable_note(self) -> ScanVulnerability:
        """An INFO finding explaining that the tool is not installed.

        Returned instead of fabricated results: the honest outcome of "this
        tool did not run" is a note saying so, not invented vulnerabilities.
        """
        return ScanVulnerability(
            cve_id=None,
            cvss_score=0.0,
            severity="INFO",
            description=(
                f"{self.name} is not installed, so this check did not run. "
                f"{self.install_hint}"
            ),
            affected_host="",
            source_scanner=self.name,
            raw_output={"type": "not_installed"},
        )
