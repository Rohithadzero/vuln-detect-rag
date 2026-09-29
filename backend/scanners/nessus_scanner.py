from scanners.base import ScannerAdapter, ScanVulnerability


class NessusScanner(ScannerAdapter):
    """Tenable Nessus adapter — not runnable.

    Nessus Essentials is free but capped at 16 IP addresses and gated behind
    registration and an activation code, so it cannot be presented as a freely
    runnable integration. This adapter reports that it did not run and never
    returns invented findings.
    """

    name = "nessus"
    free = False
    requires_licence = True
    licence_note = (
        "Nessus Essentials is free but limited to 16 IPs and requires "
        "registration; Nessus Professional is a paid product. This adapter "
        "does not run scans."
    )

    def is_available(self) -> bool:
        return False  # Requires Nessus installation

    def scan(self, target: str) -> list[ScanVulnerability]:
        return self._no_result(target)

