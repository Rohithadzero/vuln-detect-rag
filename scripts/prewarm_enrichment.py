"""Pre-warm the NVD enrichment cache for a corpus, resumably.

Why this exists
---------------
`rag_engine.index_cves()` enriches every record before indexing, and
`CVEEnricher.load_nvd()` fetches uncached CVEs one at a time at 6.5 s apart --
NVD's documented rate limit without a key. For a 200-CVE corpus that is ~22
minutes before a single vector is written.

The problem is not that it is slow, it is that it is *all-or-nothing*:
`load_nvd()` writes its cache only after the whole loop finishes, so a run
stopped at minute 21 saves nothing and starts over from zero.

This script does the same fetch and writes the cache every `--batch` records.
Stop it whenever; rerun it and it picks up from the last batch. Once the cache
is warm, `run_eval_200.py` seeds in seconds because every lookup is a cache hit.

    python prewarm_enrichment.py                       # 200-CVE corpus
    python prewarm_enrichment.py --corpus <path> --batch 10

Uses the project's own CVEEnricher for parsing and cache I/O, so the cache this
writes is exactly the cache the indexer would have written -- same file, same
schema, same TTL semantics.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                                  # repository root
DATA = ROOT / "backend" / "data"

sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", default=str(DATA / "sample_nvd_200.json"))
    parser.add_argument("--batch", type=int, default=10,
                        help="write the cache every N fetches (default 10)")
    parser.add_argument("--delay", type=float, default=None,
                        help="seconds between requests (default: the "
                             "enricher's own 6.5, or 0.7 with NVD_API_KEY)")
    args = parser.parse_args()

    from services.enrichment import CVEEnricher, NVD_URL, NVD_DELAY_SECONDS

    delay = args.delay
    if delay is None:
        delay = 0.7 if os.getenv("NVD_API_KEY") else NVD_DELAY_SECONDS

    with open(args.corpus, encoding="utf-8") as handle:
        wanted = [e["cve_id"].upper() for e in json.load(handle)]

    enricher = CVEEnricher()
    cached = enricher._read_cache("nvd", ttl=30 * 24 * 3600) or {}
    missing = [c for c in wanted if c not in cached]

    print("corpus   : %s" % args.corpus)
    print("wanted   : %d CVEs" % len(wanted))
    print("cached   : %d" % (len(wanted) - len(missing)))
    print("to fetch : %d at %.1fs apart (~%.0f min)"
          % (len(missing), delay, len(missing) * delay / 60.0))
    if not missing:
        print("nothing to do; cache is warm")
        return 0

    fetched = failed = 0
    for index, cve_id in enumerate(missing):
        if index:
            time.sleep(delay)
        payload = enricher._get(NVD_URL, params={"cveId": cve_id}, timeout=45)
        vulns = (payload or {}).get("vulnerabilities") or []
        if vulns:
            cached[cve_id] = enricher._parse_nvd(vulns[0].get("cve", {}))
            fetched += 1
        else:
            failed += 1

        # Checkpoint. This is the whole point of the script: a stop here costs
        # at most `batch` lookups, not the entire run.
        if (index + 1) % args.batch == 0 or index == len(missing) - 1:
            enricher._write_cache("nvd", cached)
            print("  %3d/%d fetched (%d empty) -- cache written, %d entries"
                  % (index + 1, len(missing), failed, len(cached)))

    print("\ndone: %d fetched, %d returned nothing, %d total in cache"
          % (fetched, failed, len(cached)))

    have = sum(1 for c in wanted if c in cached)
    with_cwe = sum(1 for c in wanted
                   if cached.get(c, {}).get("cwe_ids"))
    print("corpus coverage: %d/%d have an NVD record, %d carry a CWE"
          % (have, len(wanted), with_cwe))
    return 0


if __name__ == "__main__":
    sys.exit(main())
