"""Threat-intelligence enrichment from free, no-key public sources.

The bundled CVE corpus carries only a description, a CVSS score and a
remediation string. That is thin evidence for an LLM: it cannot say whether a
vulnerability is actually being exploited, how likely exploitation is, what
weakness class it belongs to, or how an attacker would reach it. Those are the
first questions a practitioner asks, and an answer that cannot address them is
of little operational use.

This module adds that context from four public sources, all free and none
requiring an API key or registration:

  - CISA KEV      Known Exploited Vulnerabilities catalogue: ground truth on
                  what is being exploited in the wild right now.
  - FIRST EPSS    Exploit Prediction Scoring System: probability of
                  exploitation in the next 30 days, plus a percentile.
  - NVD 2.0 API   Authoritative CVSS vectors, CWE weakness class, affected
                  configurations (CPE), publication dates, references.
  - OSV.dev       Affected package and ecosystem data for software
                  dependencies.

Every lookup is best-effort. If the network is unavailable the enrichment is
skipped and indexing continues with what the local corpus already provides,
because degraded context is much better than a failed index.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("vulndetect")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/vulns"

#: NVD asks for at most 5 requests per 30 seconds without an API key.
NVD_DELAY_SECONDS = 6.5

#: Cached feeds older than this are refetched.
CACHE_TTL_SECONDS = 24 * 3600


class CVEEnricher:
    """Fetches and caches free threat intelligence for CVE records."""

    def __init__(self, cache_dir: Optional[str] = None, offline: bool = False):
        """Initialize the enricher.

        Args:
            cache_dir: Where to persist fetched feeds.
            offline: Skip all network calls and use only cached data.
        """
        default_cache = Path(__file__).resolve().parents[1] / "data" / "enrichment"
        self.cache_dir = Path(cache_dir or default_cache)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.offline = offline or os.getenv("ENRICHMENT_OFFLINE", "0") == "1"

        self._kev: Optional[Dict[str, Dict[str, Any]]] = None
        self._epss: Dict[str, Dict[str, float]] = {}
        self._nvd: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_path(self, name: str) -> Path:
        return self.cache_dir / f"{name}.json"

    def _read_cache(self, name: str, ttl: int = CACHE_TTL_SECONDS) -> Optional[Any]:
        """Return cached data if present and fresh enough."""
        path = self._cache_path(name)
        if not path.exists():
            return None
        age = time.time() - path.stat().st_mtime
        if age > ttl and not self.offline:
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Could not read enrichment cache %s: %s", name, e)
            return None

    def _write_cache(self, name: str, data: Any) -> None:
        try:
            with open(self._cache_path(name), "w", encoding="utf-8") as handle:
                json.dump(data, handle)
        except OSError as e:
            logger.warning("Could not write enrichment cache %s: %s", name, e)

    def _get(self, url: str, **kwargs) -> Optional[Any]:
        """GET JSON, returning None instead of raising on any failure."""
        if self.offline:
            return None
        try:
            import requests

            response = requests.get(
                url,
                timeout=kwargs.pop("timeout", 30),
                headers={"User-Agent": "VulnDetectRAG/3.5 (security research)"},
                **kwargs,
            )
            if response.status_code != 200:
                logger.warning("%s returned HTTP %d", url, response.status_code)
                return None
            return response.json()
        except Exception as e:
            logger.warning("Request to %s failed: %s", url, e)
            return None

    # ------------------------------------------------------------------
    # CISA KEV
    # ------------------------------------------------------------------

    @property
    def kev(self) -> Dict[str, Dict[str, Any]]:
        """CISA Known Exploited Vulnerabilities, keyed by CVE ID.

        This is the single most decision-relevant signal available: presence
        here means confirmed in-the-wild exploitation, which outranks any CVSS
        score for prioritisation.
        """
        if self._kev is not None:
            return self._kev

        cached = self._read_cache("cisa_kev")
        if cached is None:
            payload = self._get(KEV_URL, timeout=60)
            if payload:
                cached = payload
                self._write_cache("cisa_kev", payload)

        entries: Dict[str, Dict[str, Any]] = {}
        if cached:
            for item in cached.get("vulnerabilities", []):
                cve_id = item.get("cveID", "").upper()
                if cve_id:
                    entries[cve_id] = item
            logger.info("Loaded CISA KEV catalogue: %d known-exploited CVEs",
                        len(entries))

        self._kev = entries
        return entries

    # ------------------------------------------------------------------
    # EPSS
    # ------------------------------------------------------------------

    def load_epss(self, cve_ids: Iterable[str]) -> Dict[str, Dict[str, float]]:
        """Fetch EPSS scores for the given CVEs.

        EPSS answers "how likely is exploitation soon", which is different from
        CVSS's "how bad would it be". Together they let the assistant reason
        about priority rather than only severity.
        """
        wanted = [c.upper() for c in cve_ids if c]
        if not wanted:
            return {}

        cached = self._read_cache("epss") or {}
        missing = [c for c in wanted if c not in cached]

        # The API accepts a comma-separated list; batch to keep URLs sane.
        for start in range(0, len(missing), 100):
            batch = missing[start:start + 100]
            payload = self._get(EPSS_URL, params={"cve": ",".join(batch)})
            if not payload:
                break
            for item in payload.get("data", []):
                cve_id = item.get("cve", "").upper()
                if not cve_id:
                    continue
                try:
                    cached[cve_id] = {
                        "epss": float(item.get("epss", 0.0)),
                        "percentile": float(item.get("percentile", 0.0)),
                    }
                except (TypeError, ValueError):
                    continue

        if cached:
            self._write_cache("epss", cached)

        self._epss = cached
        return {c: cached[c] for c in wanted if c in cached}

    # ------------------------------------------------------------------
    # NVD
    # ------------------------------------------------------------------

    def load_nvd(self, cve_ids: Iterable[str], limit: Optional[int] = None) -> Dict[str, Dict[str, Any]]:
        """Fetch authoritative NVD records (CWE, CVSS vector, CPE, dates).

        NVD is rate-limited to roughly 5 requests per 30 seconds without a key,
        so this is deliberately slow and cached aggressively. `limit` caps how
        many uncached CVEs are fetched in one run.
        """
        wanted = [c.upper() for c in cve_ids if c]
        cached = self._read_cache("nvd", ttl=30 * 24 * 3600) or {}
        missing = [c for c in wanted if c not in cached]

        if limit is not None:
            missing = missing[:limit]

        for index, cve_id in enumerate(missing):
            if index:
                time.sleep(NVD_DELAY_SECONDS)
            payload = self._get(NVD_URL, params={"cveId": cve_id}, timeout=45)
            if not payload:
                continue
            vulns = payload.get("vulnerabilities") or []
            if not vulns:
                continue
            cached[cve_id] = self._parse_nvd(vulns[0].get("cve", {}))

        if cached:
            self._write_cache("nvd", cached)

        self._nvd = cached
        return {c: cached[c] for c in wanted if c in cached}

    @staticmethod
    def _parse_nvd(cve: Dict[str, Any]) -> Dict[str, Any]:
        """Reduce an NVD record to the fields worth putting in a prompt."""
        record: Dict[str, Any] = {
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "vuln_status": cve.get("vulnStatus", ""),
        }

        # CWE weakness classes — the "what kind of bug is this" signal.
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            for description in weakness.get("description", []):
                value = description.get("value", "")
                if value and value.startswith("CWE-"):
                    weaknesses.append(value)
        record["cwe_ids"] = sorted(set(weaknesses))

        # Prefer CVSS v3.1, then v3.0, then v2.
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if not entries:
                continue
            data = entries[0].get("cvssData", {})
            record.update({
                "cvss_version": data.get("version", ""),
                "cvss_vector": data.get("vectorString", ""),
                "cvss_base_score": data.get("baseScore"),
                "attack_vector": data.get("attackVector", ""),
                "attack_complexity": data.get("attackComplexity", ""),
                "privileges_required": data.get("privilegesRequired", ""),
                "user_interaction": data.get("userInteraction", ""),
                "confidentiality_impact": data.get("confidentialityImpact", ""),
                "integrity_impact": data.get("integrityImpact", ""),
                "availability_impact": data.get("availabilityImpact", ""),
            })
            break

        # Affected products, from CPE match criteria.
        products = set()
        for configuration in cve.get("configurations", []):
            for node in configuration.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    # cpe:2.3:a:vendor:product:version:...
                    if len(parts) > 5:
                        vendor, product = parts[3], parts[4]
                        if vendor and product:
                            products.add(f"{vendor} {product}".replace("_", " "))
        record["affected_products"] = sorted(products)[:20]

        references = [
            ref.get("url", "") for ref in cve.get("references", [])
            if ref.get("url")
        ]
        record["references"] = references[:10]

        return record

    # ------------------------------------------------------------------
    # Combined
    # ------------------------------------------------------------------

    def enrich(self, cve_ids: List[str], include_nvd: bool = True,
               nvd_limit: Optional[int] = None) -> Dict[str, Dict[str, Any]]:
        """Gather every available signal for a set of CVEs.

        Args:
            cve_ids: CVE identifiers to enrich.
            include_nvd: Whether to query NVD (slow, rate-limited).
            nvd_limit: Cap on uncached NVD lookups this run.

        Returns:
            Mapping of CVE ID to its enrichment record.
        """
        normalized = [c.upper() for c in cve_ids if c]
        kev = self.kev
        epss = self.load_epss(normalized)
        nvd = self.load_nvd(normalized, limit=nvd_limit) if include_nvd else {}

        enriched: Dict[str, Dict[str, Any]] = {}
        for cve_id in normalized:
            record: Dict[str, Any] = {}

            kev_entry = kev.get(cve_id)
            if kev_entry:
                record["kev"] = True
                record["kev_date_added"] = kev_entry.get("dateAdded", "")
                record["kev_due_date"] = kev_entry.get("dueDate", "")
                record["kev_action"] = kev_entry.get("requiredAction", "")
                record["kev_ransomware"] = (
                    kev_entry.get("knownRansomwareCampaignUse", "Unknown")
                )
                record["kev_vendor"] = kev_entry.get("vendorProject", "")
                record["kev_product"] = kev_entry.get("product", "")
            else:
                record["kev"] = False

            epss_entry = epss.get(cve_id)
            if epss_entry:
                record["epss_score"] = epss_entry["epss"]
                record["epss_percentile"] = epss_entry["percentile"]

            if cve_id in nvd:
                record.update(nvd[cve_id])

            enriched[cve_id] = record

        return enriched

    @staticmethod
    def describe(cve_id: str, record: Dict[str, Any]) -> str:
        """Render an enrichment record as prose for the indexed document.

        Written as sentences rather than key-value pairs because the retrieved
        chunk is read by a language model: "actively exploited in the wild"
        carries meaning that `kev=true` does not.
        """
        if not record:
            return ""

        lines: List[str] = []

        if record.get("kev"):
            detail = "This vulnerability is on the CISA Known Exploited Vulnerabilities catalogue: it is confirmed to be exploited in the wild."
            if record.get("kev_date_added"):
                detail += f" Added {record['kev_date_added']}."
            if record.get("kev_due_date"):
                detail += f" US federal remediation deadline {record['kev_due_date']}."
            if str(record.get("kev_ransomware", "")).lower() == "known":
                detail += " It is known to be used in ransomware campaigns."
            lines.append(f"Exploitation status: {detail}")
        else:
            lines.append(
                "Exploitation status: not listed on the CISA Known Exploited "
                "Vulnerabilities catalogue."
            )

        if record.get("epss_score") is not None:
            score = record["epss_score"]
            percentile = record.get("epss_percentile", 0.0)
            lines.append(
                f"Exploit likelihood (EPSS): {score:.4f} probability of "
                f"exploitation in the next 30 days, which is the "
                f"{percentile * 100:.1f}th percentile of all CVEs."
            )

        if record.get("cwe_ids"):
            lines.append(f"Weakness class: {', '.join(record['cwe_ids'])}.")

        if record.get("cvss_vector"):
            lines.append(
                f"CVSS {record.get('cvss_version', '')} vector: "
                f"{record['cvss_vector']}."
            )

        attack_bits = []
        if record.get("attack_vector"):
            attack_bits.append(f"attack vector {record['attack_vector'].lower()}")
        if record.get("attack_complexity"):
            attack_bits.append(
                f"attack complexity {record['attack_complexity'].lower()}"
            )
        if record.get("privileges_required"):
            attack_bits.append(
                f"privileges required {record['privileges_required'].lower()}"
            )
        if record.get("user_interaction"):
            attack_bits.append(
                f"user interaction {record['user_interaction'].lower()}"
            )
        if attack_bits:
            lines.append("Exploitability: " + ", ".join(attack_bits) + ".")

        if record.get("affected_products"):
            products = ", ".join(record["affected_products"][:10])
            lines.append(f"Affected products: {products}.")

        if record.get("published"):
            lines.append(f"Published: {record['published'][:10]}.")

        return "\n".join(lines)

    @staticmethod
    def metadata(record: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten an enrichment record into filterable Chroma metadata."""
        if not record:
            return {}

        meta: Dict[str, Any] = {
            "kev": bool(record.get("kev")),
        }
        for key in ("epss_score", "epss_percentile", "cvss_vector",
                    "attack_vector", "attack_complexity", "published",
                    "kev_ransomware"):
            if record.get(key) not in (None, ""):
                meta[key] = record[key]

        if record.get("cwe_ids"):
            meta["cwe_ids"] = ", ".join(record["cwe_ids"])
            meta["primary_cwe"] = record["cwe_ids"][0]
        if record.get("affected_products"):
            meta["affected_products"] = ", ".join(record["affected_products"][:10])

        return meta


#: Shared instance; feeds are cached on disk so this stays cheap.
cve_enricher = CVEEnricher()
