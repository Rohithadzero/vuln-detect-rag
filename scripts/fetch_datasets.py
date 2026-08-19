"""Fetch the MITRE datasets the knowledge graph is built from.

Four sources, each the authoritative publisher rather than a mirror:

  CWE     cwe.mitre.org  research view (CWE-1000), the weakness catalogue
          and the ChildOf/PeerOf relationships between weaknesses.
  CAPEC   capec.mitre.org  attack patterns, carrying both the CWE weaknesses
          each pattern exploits and its ATT&CK taxonomy mappings. This is the
          join that connects the weakness world to the adversary-behaviour
          world; without it CWE and ATT&CK are two disconnected components.
  ATT&CK  MITRE CTI STIX bundle, enterprise matrix.
  CVE-CWE NVD API 2.0, queried per CVE in the local corpus. The seed corpus
          carries no weakness field, so this is what anchors our own CVEs
          into the graph.

Everything lands in dataset/raw/ and is recorded in dataset/MANIFEST.json with
its source URL, SHA-256 and byte count, so a rebuild can be shown to have used
the same inputs. Files already present are skipped unless --force is given:
the point of vendoring these is that the system builds with no network.

    python scripts/fetch_datasets.py
    python scripts/fetch_datasets.py --force
    python scripts/fetch_datasets.py --only cve

NVD applies a published rate limit of 5 requests per rolling 30 seconds
without an API key. We stay under it deliberately rather than retrying into a
block; with a key in NVD_API_KEY the allowance rises and the delay drops.
"""
import argparse
import hashlib
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
DATASET = os.path.join(ROOT, "dataset")
RAW = os.path.join(DATASET, "raw")
MANIFEST = os.path.join(DATASET, "MANIFEST.json")
CORPUS = os.path.join(ROOT, "backend", "data", "sample_nvd.json")

UA = "VulnDetectRAG/4.5 (research; dataset fetch)"

SOURCES = {
    "cwe": {
        "url": "https://cwe.mitre.org/data/csv/1000.csv.zip",
        "path": "cwe_1000.csv.zip",
        "note": "CWE research view: weaknesses and their hierarchy",
    },
    "capec": {
        # View 3000, "Domains of Attack", carries 559 patterns against the 177
        # in the mechanism view 658. Both are valid CAPEC views; the wider one
        # produces a graph with materially more CWE and ATT&CK edges.
        "url": "https://capec.mitre.org/data/csv/3000.csv.zip",
        "path": "capec_3000.csv.zip",
        "note": "CAPEC attack patterns with CWE and ATT&CK mappings",
    },
    "attack": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/"
               "enterprise-attack/enterprise-attack.json",
        "path": "enterprise_attack.json",
        "note": "MITRE ATT&CK enterprise matrix, STIX 2.1 bundle",
    },
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def get(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def download(key, spec, force):
    dest = os.path.join(RAW, spec["path"])
    if os.path.exists(dest) and not force:
        print("  skip     %-22s (present, %s bytes)"
              % (spec["path"], os.path.getsize(dest)))
        return dest
    print("  fetching %-22s %s" % (spec["path"], spec["url"]))
    data = get(spec["url"])
    if not data:
        raise RuntimeError("empty response for %s" % key)
    with open(dest, "wb") as fh:
        fh.write(data)
    print("           %s bytes" % len(data))
    return dest


def fetch_cve_cwe(force):
    """Map each CVE in the local corpus to its CWE weaknesses via NVD.

    Written incrementally: a run interrupted partway keeps what it already
    resolved, because re-requesting 50 CVEs through a rate limit to recover
    from a dropped connection is a poor use of the allowance.
    """
    dest = os.path.join(DATASET, "cve_cwe.json")
    existing = {}
    if os.path.exists(dest) and not force:
        with io.open(dest, encoding="utf-8") as fh:
            existing = json.load(fh)

    with io.open(CORPUS, encoding="utf-8") as fh:
        cves = sorted({e["cve_id"] for e in json.load(fh)})

    todo = [c for c in cves if c not in existing]
    if not todo:
        print("  skip     cve_cwe.json           (all %d CVEs resolved)" % len(cves))
        return dest

    key = os.getenv("NVD_API_KEY", "").strip()
    delay = 0.8 if key else 6.5
    print("  fetching CWE mappings for %d CVEs from NVD (%s, %.1fs apart)"
          % (len(todo), "with API key" if key else "no API key", delay))

    failures = 0
    for i, cve in enumerate(todo, 1):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s" % cve
        # NVD times out and 503s often enough under the anonymous allowance
        # that a single attempt loses entries for no good reason. Note that a
        # read timeout raises TimeoutError, which is an OSError but NOT a
        # urllib URLError -- catching only URLError lets it kill the run.
        payload = None
        for attempt in range(3):
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            if key:
                req.add_header("apiKey", key)
            try:
                with urllib.request.urlopen(req, timeout=45) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                break
            except (OSError, ValueError) as exc:
                last = exc
                if attempt < 2:
                    time.sleep(delay * (attempt + 2))
        if payload is None:
            failures += 1
            print("    [%2d/%2d] %-18s FAILED: %s" % (i, len(todo), cve, last))
        else:
            try:
                vulns = payload.get("vulnerabilities") or []
                cwes = []
                if vulns:
                    for weakness in vulns[0]["cve"].get("weaknesses", []):
                        for desc in weakness.get("description", []):
                            value = desc.get("value", "")
                            # NVD emits "NVD-CWE-noinfo" and "NVD-CWE-Other"
                            # where no weakness applies or none was assigned.
                            # They are not weaknesses and must not become
                            # graph nodes; the prefix test excludes them.
                            if value.startswith("CWE-"):
                                cwes.append(value)
                existing[cve] = sorted(set(cwes))
                print("    [%2d/%2d] %-18s %s"
                      % (i, len(todo), cve, ",".join(existing[cve]) or "(none)"))
            except (KeyError, IndexError, TypeError) as exc:
                failures += 1
                print("    [%2d/%2d] %-18s BAD RESPONSE: %s" % (i, len(todo), cve, exc))
        # Persist as we go, not at the end.
        with io.open(dest, "w", encoding="utf-8") as fh:
            json.dump(existing, fh, indent=1, sort_keys=True)
        if i < len(todo):
            time.sleep(delay)

    resolved = sum(1 for v in existing.values() if v)
    print("  %d/%d CVEs carry at least one CWE (%d request failures)"
          % (resolved, len(existing), failures))
    return dest


def write_manifest(entries):
    manifest = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": "Inputs to scripts/build_knowledge_graph.py. Re-fetch with "
                "scripts/fetch_datasets.py --force.",
        "files": entries,
    }
    with io.open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    print("\nwrote %s" % os.path.relpath(MANIFEST, ROOT))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--force", action="store_true",
                    help="re-download even if the file is already present")
    ap.add_argument("--only", choices=sorted(SOURCES) + ["cve"],
                    help="fetch a single source")
    args = ap.parse_args()

    os.makedirs(RAW, exist_ok=True)

    wanted = [args.only] if args.only else sorted(SOURCES) + ["cve"]
    entries = {}

    for key in wanted:
        if key == "cve":
            print("\nCVE to CWE (NVD API 2.0)")
            path = fetch_cve_cwe(args.force)
        else:
            spec = SOURCES[key]
            print("\n%s -- %s" % (key.upper(), spec["note"]))
            path = download(key, spec, args.force)

        entries[os.path.relpath(path, DATASET).replace(os.sep, "/")] = {
            "source": SOURCES[key]["url"] if key in SOURCES
                      else "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "sha256": sha256(path),
            "bytes": os.path.getsize(path),
        }

    # Preserve entries for sources not fetched in this run.
    if os.path.exists(MANIFEST):
        with io.open(MANIFEST, encoding="utf-8") as fh:
            for name, meta in json.load(fh).get("files", {}).items():
                entries.setdefault(name, meta)

    write_manifest(entries)
    print("\nNext: python scripts/build_knowledge_graph.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
