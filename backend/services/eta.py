"""Estimated running time for a scan's background work.

A scan runs as a background task, so the caller polls for status with no sense
of how long the wait will be. This module turns the selected scanner list into
an estimate, and — once a scan has been running past its estimate — into an
honest "this is taking longer than expected" signal instead of a stuck bar.

The numbers are typical wall-clock times against a responsive host, not the
hard timeouts each tool enforces. They are estimates: a slow target, a large
attack surface, or a tool downloading templates can push the real time higher,
which is exactly the case the overrun message exists to cover.

Kept dependency-free (only the standard library) so the schema layer can import
it without risking a circular import.
"""

from datetime import datetime, timezone

#: Typical seconds each scanner takes against a responsive target.
SCANNER_ESTIMATE_SECONDS: dict[str, int] = {
    "nmap": 60,
    "nuclei": 120,
    "openvas": 600,
    "zap": 300,
    "nikto": 240,
    "tlsscan": 90,
    "whatweb": 45,
    "webprobe": 90,
    "trivy": 60,
    "osv": 30,
    "grype": 60,
    "nessus": 60,
    "burp": 300,
}

#: Fixed overhead for aggregation and vector-store indexing after scanning.
OVERHEAD_SECONDS = 20

#: Fallback for a scanner not in the table above.
_DEFAULT_SCANNER_SECONDS = 120


def estimate_total_seconds(scanners: list[str] | None) -> int:
    """Total estimated running time for a scan using ``scanners``."""
    names = scanners or []
    total = sum(
        SCANNER_ESTIMATE_SECONDS.get(name, _DEFAULT_SCANNER_SECONDS) for name in names
    )
    return total + OVERHEAD_SECONDS


def _humanize(seconds: int) -> str:
    """Render a duration as a short human string (e.g. '2m 30s')."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m" if secs == 0 else f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h" if minutes == 0 else f"{hours}h {minutes}m"


def _elapsed_seconds(started_at) -> int:
    if not started_at:
        return 0
    started = started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return max(0, int((datetime.now(timezone.utc) - started).total_seconds()))


def compute_eta(status: str, scanners, started_at, completed_at) -> dict:
    """Estimate for a scan, shaped for the API response.

    Returns eta_seconds (the full estimate), eta_remaining_seconds (0 once
    done or overrun), overrun (running longer than estimated), and a
    human-readable eta_message.
    """
    total = estimate_total_seconds(scanners)

    if status == "pending":
        return {
            "eta_seconds": total,
            "eta_remaining_seconds": total,
            "overrun": False,
            "eta_message": f"Estimated {_humanize(total)}.",
        }

    if status == "running":
        elapsed = _elapsed_seconds(started_at)
        remaining = total - elapsed
        if remaining > 0:
            return {
                "eta_seconds": total,
                "eta_remaining_seconds": remaining,
                "overrun": False,
                "eta_message": f"About {_humanize(remaining)} left.",
            }
        return {
            "eta_seconds": total,
            "eta_remaining_seconds": 0,
            "overrun": True,
            "eta_message": (
                f"Taking longer than the estimated {_humanize(total)}; "
                f"more time is needed. Running for {_humanize(elapsed)} so far."
            ),
        }

    # completed / failed / anything terminal
    return {
        "eta_seconds": total,
        "eta_remaining_seconds": 0,
        "overrun": False,
        "eta_message": "",
    }
