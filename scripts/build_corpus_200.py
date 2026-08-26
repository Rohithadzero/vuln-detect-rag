"""Build the 200-CVE balanced evaluation corpus the paper's Table I describes.

The reported runs used a 50-CVE corpus skewed hard toward CRITICAL and HIGH
(26/18/5/1 across the four bands). Reviewer point 1 asks for the larger set that
Table I advertises; this script builds it, 50 CVEs per CVSS v3 severity band,
straight from the NVD 2.0 API.

Output goes to a NEW file. `sample_nvd.json` is left alone: it is the corpus
that produced `eval_results_v2.json`, and overwriting it would make the
published numbers unreproducible.

    python build_corpus_200.py                 # writes sample_nvd_200.json
    python build_corpus_200.py --per-band 50

Schema matches sample_nvd.json exactly -- cve_id, cvss_score, severity,
description, solution, references, exploit_available, source -- because
run_eval.py, seed_cve_data.py and the SQLite model all read those keys by name.

Two fields need a word of explanation, because NVD does not publish them in the
form this corpus wants:

  solution   NVD carries no remediation prose. Where a reference is tagged
             "Patch" or "Vendor Advisory", the solution points at that tagged
             URL; otherwise it says to consult the vendor advisory. This is
             derived from real tagged references, never invented, but it is
             thinner than the hand-written remediation text in the original 50.
             That matters because run_eval.py builds its ROUGE reference as
             description + " Remediation: " + solution, so reference text for
             these records is description-dominated. Record the choice in the
             paper rather than leaving it implicit.

  exploit_available
             Set from the NVD KEV flag (cisaExploitAdd present) rather than
             guessed, so it means "confirmed exploited in the wild", which is
             narrower than the original corpus's usage.

The five control CVEs in run_eval.CONTROL_CVES are excluded explicitly: those
questions only test refusal while their subjects are genuinely absent.
"""
import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))   # repository root
OUT = os.path.join(ROOT, "backend", "data", "sample_nvd_200.json")
EXISTING = os.path.join(ROOT, "backend", "data", "sample_nvd.json")

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "VulnDetectRAG/4.5 (research; balanced eval corpus build)"
BANDS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Absent-by-design: these are the refusal controls.
CONTROL_CVES = {
    "CVE-2019-0708", "CVE-2017-0144", "CVE-2014-0160",
    "CVE-2018-7600", "CVE-2016-5195",
}

# NVD allows 5 requests per rolling 30 s without a key. Stay under it rather
# than retrying into a block; a key in NVD_API_KEY raises the allowance.
DELAY = 1.0 if os.getenv("NVD_API_KEY") else 7.0


def fetch(params):
    """One NVD page, with the documented rate limit respected."""
    url = API + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": UA}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.getenv("NVD_API_KEY")
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429, 503) and attempt < 3:
                wait = 30 * (attempt + 1)
                print("  HTTP %d, backing off %ds" % (exc.code, wait))
                time.sleep(wait)
                continue
            raise
        except Exception as exc:                       # transient network
            if attempt < 3:
                print("  %s, retrying" % type(exc).__name__)
                time.sleep(10)
                continue
            raise
    raise SystemExit("NVD did not answer after 4 attempts")


def english_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return " ".join((d.get("value") or "").split())
    return ""


def cvss_v3(cve):
    """(score, severity) from the preferred CVSS v3.1 metric, else v3.0."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for entry in metrics.get(key, []):
            data = entry.get("cvssData", {})
            if data.get("baseScore") is not None:
                return float(data["baseScore"]), data.get("baseSeverity", "")
    return None, ""


def solution_for(cve):
    """Remediation text derived from NVD's own reference tags, never invented."""
    refs = cve.get("references", [])
    for wanted in ("Patch", "Vendor Advisory"):
        for ref in refs:
            if wanted in (ref.get("tags") or []):
                return ("Apply the vendor fix; see the %s at %s."
                        % (wanted.lower(), ref.get("url")))
    return ("Consult the vendor advisory for the affected product and upgrade "
            "to a fixed version.")


def normalize(cve):
    """One NVD record in the corpus schema, or None if unusable."""
    cve_id = cve.get("id", "")
    if not cve_id or cve_id in CONTROL_CVES:
        return None
    if cve.get("vulnStatus") in ("Rejected", "Awaiting Analysis"):
        return None
    description = english_description(cve)
    # Short or placeholder descriptions cannot support a description-style
    # question, which is half the question set.
    if len(description) < 80 or description.lower().startswith("rejected"):
        return None
    score, severity = cvss_v3(cve)
    if score is None or severity not in BANDS:
        return None
    urls = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    return {
        "cve_id": cve_id,
        "cvss_score": score,
        "severity": severity,
        "description": description,
        "solution": solution_for(cve),
        "references": urls[:2] or [
            "https://nvd.nist.gov/vuln/detail/%s" % cve_id],
        "exploit_available": bool(cve.get("cisaExploitAdd")),
        "source": "NVD",
    }


def collect(band, want, pages, seed):
    """Sample `want` usable records for one severity band, newest first.

    Two things this has to get right that a naive query does not:

    startIndex  NVD returns results oldest-first, so startIndex=0 yields a
                corpus centred on 2015-2016. That would quietly strengthen the
                no-retrieval baseline -- models have seen those CVEs many times
                -- and the paper's whole premise is recent vulnerabilities past
                the knowledge cutoff. So page in from the TAIL of the result
                set, which is the newest end.

    band match  cvssV3Severity filters on any CVSS v3 metric attached to the
                record, including secondary-source ones, while cvss_v3() reads
                the preferred metric. The two disagree often enough to skew the
                bands (54 MEDIUM / 46 LOW on the first build), so records whose
                preferred metric lands in a different band are dropped here
                rather than counted toward the wrong one.
    """
    head = fetch({"cvssV3Severity": band, "resultsPerPage": 1})
    total = head.get("totalResults", 0)
    time.sleep(DELAY)

    pool, seen = [], set()
    for page in range(pages):
        index = max(0, total - 2000 * (page + 1))
        print("  %s page %d (startIndex=%d of %d)" % (band, page + 1, index, total))
        payload = fetch({
            "cvssV3Severity": band,
            "resultsPerPage": 2000,
            "startIndex": index,
        })
        items = payload.get("vulnerabilities", [])
        if not items:
            break
        for item in items:
            record = normalize(item.get("cve", {}))
            # Keep only records the preferred metric actually puts in this band.
            if record and record["severity"] == band and record["cve_id"] not in seen:
                seen.add(record["cve_id"])
                pool.append(record)
        if index == 0:
            break
        time.sleep(DELAY)

    print("  %s: %d usable in pool" % (band, len(pool)))
    if len(pool) <= want:
        return pool
    # Deterministic sample, so a rebuild evaluates the same corpus.
    return random.Random(seed + band).sample(pool, want)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-band", type=int, default=50,
                        help="CVEs per CVSS severity band (default 50)")
    parser.add_argument("--pages", type=int, default=2,
                        help="NVD pages of 2000 to draw each band from")
    parser.add_argument("--seed", default="vdr-2026",
                        help="sampling seed, recorded in the sidecar file")
    parser.add_argument("--out", default=OUT)
    args = parser.parse_args()

    corpus = []
    for band in BANDS:
        corpus.extend(collect(band, args.per_band, args.pages, args.seed))
        time.sleep(DELAY)

    corpus.sort(key=lambda e: e["cve_id"])
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(corpus, handle, indent=2)

    counts = {}
    for entry in corpus:
        counts[entry["severity"]] = counts.get(entry["severity"], 0) + 1
    years = {}
    for entry in corpus:
        year = entry["cve_id"].split("-")[1]
        years[year] = years.get(year, 0) + 1

    print("\nwrote %s" % args.out)
    print("  %d records" % len(corpus))
    print("  severity: %s" % counts)
    print("  years   : %s" % dict(sorted(years.items())))
    print("  KEV     : %d" % sum(1 for e in corpus if e["exploit_available"]))

    # Overlap with the pilot corpus, which the paper will want to state.
    if os.path.exists(EXISTING):
        with open(EXISTING, encoding="utf-8") as handle:
            old = {e["cve_id"] for e in json.load(handle)}
        print("  overlap with the 50-CVE pilot corpus: %d"
              % len({e["cve_id"] for e in corpus} & old))

    for cve_id in CONTROL_CVES:
        assert cve_id not in {e["cve_id"] for e in corpus}, cve_id
    print("  all 5 refusal controls confirmed absent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
