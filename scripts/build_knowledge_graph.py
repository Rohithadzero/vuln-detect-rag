"""Build the CVE -> CWE -> CAPEC -> ATT&CK knowledge graph.

The four MITRE datasets each describe one layer of the same story, and none of
them answers an analyst's actual question on its own:

    CVE      this specific vulnerability, in this product
    CWE      the class of programming error behind it
    CAPEC    the attack patterns that exploit that class of error
    ATT&CK   the adversary techniques those patterns correspond to

A scanner reports the first. Triage needs the last. This joins them into one
directed graph so the path can be walked in either direction: forward from a
finding to the adversary behaviour it enables, or backward from a technique to
the findings in your estate that would let an adversary use it.

Edges come from the publishers' own cross-references, never inferred:

    CVE   -[EXPLOITS]->      CWE      NVD weakness assignments
    CWE   -[CHILD_OF]->      CWE      CWE-1000 research view hierarchy
    CAPEC -[TARGETS]->       CWE      CAPEC "Related Weaknesses"
    CAPEC -[CHILD_OF]->      CAPEC    CAPEC "Related Attack Patterns"
    CAPEC -[MAPS_TO]->       ATTACK   CAPEC ATT&CK taxonomy mappings

Output is written to dataset/:

    knowledge_graph.json     node-link JSON, what the application loads
    knowledge_graph.cypher   Neo4j import script, for anyone who wants to
                             query this in Cypher rather than in process

The graph is held in NetworkX rather than requiring a Neo4j server, because
the system is meant to run with no external services -- adding a mandatory
database daemon would cost the local-operation property to buy query syntax
we do not need. The Cypher export exists so that choice is not a lock-in.

    python scripts/build_knowledge_graph.py
    python scripts/build_knowledge_graph.py --stats
"""
import argparse
import csv
import io
import json
import os
import re
import sys
import zipfile

import networkx as nx

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
DATASET = os.path.join(ROOT, "dataset")
RAW = os.path.join(DATASET, "raw")

CWE_ZIP = os.path.join(RAW, "cwe_1000.csv.zip")
CAPEC_ZIP = os.path.join(RAW, "capec_3000.csv.zip")
ATTACK_JSON = os.path.join(RAW, "enterprise_attack.json")
CVE_CWE = os.path.join(DATASET, "cve_cwe.json")
CORPUS = os.path.join(ROOT, "backend", "data", "sample_nvd.json")

OUT_JSON = os.path.join(DATASET, "knowledge_graph.json")
OUT_CYPHER = os.path.join(DATASET, "knowledge_graph.cypher")

# CWE and CAPEC pack structured fields into one CSV cell with :: separators,
# e.g. "::NATURE:ChildOf:CWE ID:319:VIEW ID:1000:ORDINAL:Primary::".
RE_CWE_PARENT = re.compile(r"NATURE:ChildOf:CWE ID:(\d+)")
RE_CAPEC_PARENT = re.compile(r"NATURE:ChildOf:CAPEC ID:(\d+)")
RE_ATTACK_ENTRY = re.compile(
    r"TAXONOMY NAME:ATTACK:ENTRY ID:([0-9.]+)(?::ENTRY NAME:([^:]*))?"
)


def read_zip_csv(path, member=None):
    with zipfile.ZipFile(path) as z:
        member = member or z.namelist()[0]
        text = z.read(member).decode("utf-8-sig")
    return list(csv.DictReader(io.StringIO(text)))


def trim(text, limit=600):
    """Collapse whitespace and cap length.

    Descriptions are carried into the graph so retrieval can read them, but a
    CWE extended description can run to several thousand characters and the
    graph is loaded into memory on every request.
    """
    text = re.sub(r"\s+", " ", (text or "").strip())
    return text[:limit]


def add_cwe(g):
    rows = read_zip_csv(CWE_ZIP, "1000.csv")
    for row in rows:
        cid = (row.get("CWE-ID") or "").strip()
        if not cid:
            continue
        node = "CWE-%s" % cid
        g.add_node(
            node,
            kind="cwe",
            name=row.get("Name", "").strip(),
            abstraction=row.get("Weakness Abstraction", "").strip(),
            description=trim(row.get("Description")),
            mitigations=trim(row.get("Potential Mitigations"), 400),
            likelihood=row.get("Likelihood of Exploit", "").strip(),
        )
    for row in rows:
        cid = (row.get("CWE-ID") or "").strip()
        if not cid:
            continue
        for parent in RE_CWE_PARENT.findall(row.get("Related Weaknesses") or ""):
            if g.has_node("CWE-%s" % parent):
                g.add_edge("CWE-%s" % cid, "CWE-%s" % parent, relation="CHILD_OF")
    return len(rows)


def add_capec(g):
    rows = read_zip_csv(CAPEC_ZIP, "3000.csv")
    # The ID column ships as "'ID" -- a leading apostrophe left by the
    # spreadsheet export that produced the file. Resolve it rather than
    # hard-coding, so a future export without it still parses.
    id_col = next((c for c in rows[0] if c.strip().strip("'") == "ID"), "'ID")

    targets = maps = 0
    for row in rows:
        pid = (row.get(id_col) or "").strip()
        if not pid:
            continue
        node = "CAPEC-%s" % pid
        g.add_node(
            node,
            kind="capec",
            name=row.get("Name", "").strip(),
            abstraction=row.get("Abstraction", "").strip(),
            description=trim(row.get("Description")),
            severity=row.get("Typical Severity", "").strip(),
            likelihood=row.get("Likelihood Of Attack", "").strip(),
            prerequisites=trim(row.get("Prerequisites"), 300),
            mitigations=trim(row.get("Mitigations"), 400),
        )

    for row in rows:
        pid = (row.get(id_col) or "").strip()
        if not pid:
            continue
        node = "CAPEC-%s" % pid

        # "::276::285::434::" -- bare CWE numbers between separators.
        for cwe in re.findall(r"::(\d+)", row.get("Related Weaknesses") or ""):
            if g.has_node("CWE-%s" % cwe):
                g.add_edge(node, "CWE-%s" % cwe, relation="TARGETS")
                targets += 1

        for parent in RE_CAPEC_PARENT.findall(row.get("Related Attack Patterns") or ""):
            if g.has_node("CAPEC-%s" % parent):
                g.add_edge(node, "CAPEC-%s" % parent, relation="CHILD_OF")

        for tid, tname in RE_ATTACK_ENTRY.findall(row.get("Taxonomy Mappings") or ""):
            attack = "T%s" % tid
            if not g.has_node(attack):
                # Placeholder: the STIX bundle fills in the real name and
                # description if the technique is present there.
                g.add_node(attack, kind="attack", name=(tname or "").strip(),
                           description="", tactics=[], url="")
            g.add_edge(node, attack, relation="MAPS_TO")
            maps += 1

    return len(rows), targets, maps


def add_attack(g):
    with io.open(ATTACK_JSON, encoding="utf-8") as fh:
        bundle = json.load(fh)

    added = enriched = 0
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        tid = None
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
                url = ref.get("url", "")
                break
        if not tid:
            continue
        tactics = [p.get("phase_name") for p in obj.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        attrs = dict(
            kind="attack",
            name=obj.get("name", ""),
            description=trim(obj.get("description")),
            tactics=tactics,
            url=url,
        )
        if g.has_node(tid):
            enriched += 1
        else:
            added += 1
        g.add_node(tid, **attrs)
    return added, enriched


def add_cves(g):
    with io.open(CORPUS, encoding="utf-8") as fh:
        corpus = {e["cve_id"]: e for e in json.load(fh)}

    mapping = {}
    if os.path.exists(CVE_CWE):
        with io.open(CVE_CWE, encoding="utf-8") as fh:
            mapping = json.load(fh)

    linked = orphan = 0
    for cve_id, entry in sorted(corpus.items()):
        g.add_node(
            cve_id,
            kind="cve",
            name=cve_id,
            description=trim(entry.get("description")),
            cvss=entry.get("cvss_score", 0.0),
            severity=entry.get("severity", ""),
            solution=trim(entry.get("solution"), 300),
            exploit_available=bool(entry.get("exploit_available")),
        )
        cwes = [c for c in mapping.get(cve_id, []) if g.has_node(c)]
        for cwe in cwes:
            g.add_edge(cve_id, cwe, relation="EXPLOITS")
        if cwes:
            linked += 1
        else:
            orphan += 1
    return len(corpus), linked, orphan


def write_cypher(g, path):
    """Emit a Neo4j import script.

    One MERGE per node and per edge. MERGE rather than CREATE so the script is
    idempotent: running it twice does not double the graph.
    """
    def esc(value):
        return str(value).replace("\\", "\\\\").replace("'", "\\'")

    label = {"cve": "CVE", "cwe": "CWE", "capec": "CAPEC", "attack": "Technique"}

    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("// VulnDetectRAG knowledge graph -- Neo4j import\n")
        fh.write("// Generated by scripts/build_knowledge_graph.py\n")
        fh.write("// Usage: cypher-shell -f knowledge_graph.cypher\n\n")
        for kind, lab in sorted(label.items()):
            fh.write("CREATE CONSTRAINT %s_id IF NOT EXISTS "
                     "FOR (n:%s) REQUIRE n.id IS UNIQUE;\n" % (kind, lab))
        fh.write("\n")

        for node, attrs in g.nodes(data=True):
            lab = label.get(attrs.get("kind"), "Node")
            props = ["id: '%s'" % esc(node), "name: '%s'" % esc(attrs.get("name", ""))]
            if attrs.get("description"):
                props.append("description: '%s'" % esc(attrs["description"]))
            if attrs.get("kind") == "cve":
                props.append("cvss: %s" % (attrs.get("cvss") or 0.0))
                props.append("severity: '%s'" % esc(attrs.get("severity", "")))
            fh.write("MERGE (n:%s {id: '%s'}) SET n += {%s};\n"
                     % (lab, esc(node), ", ".join(props)))
        fh.write("\n")

        for src, dst, attrs in g.edges(data=True):
            fh.write("MATCH (a {id: '%s'}), (b {id: '%s'}) "
                     "MERGE (a)-[:%s]->(b);\n"
                     % (esc(src), esc(dst), attrs.get("relation", "RELATED")))


def summarize(g):
    kinds = {}
    for _, attrs in g.nodes(data=True):
        kinds[attrs.get("kind", "?")] = kinds.get(attrs.get("kind", "?"), 0) + 1
    rels = {}
    for _, _, attrs in g.edges(data=True):
        r = attrs.get("relation", "?")
        rels[r] = rels.get(r, 0) + 1
    return kinds, rels


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--stats", action="store_true",
                    help="print reachability statistics for the corpus CVEs")
    args = ap.parse_args()

    missing = [p for p in (CWE_ZIP, CAPEC_ZIP, ATTACK_JSON) if not os.path.exists(p)]
    if missing:
        print("Missing inputs:", file=sys.stderr)
        for p in missing:
            print("  %s" % os.path.relpath(p, ROOT), file=sys.stderr)
        print("\nRun: python scripts/fetch_datasets.py", file=sys.stderr)
        return 1

    g = nx.DiGraph()

    n_cwe = add_cwe(g)
    print("CWE     %4d weaknesses" % n_cwe)

    n_capec, targets, maps = add_capec(g)
    print("CAPEC   %4d patterns, %d TARGETS edges to CWE, %d MAPS_TO edges to ATT&CK"
          % (n_capec, targets, maps))

    added, enriched = add_attack(g)
    print("ATT&CK  %4d techniques added, %d referenced by CAPEC and enriched"
          % (added, enriched))

    n_cve, linked, orphan = add_cves(g)
    print("CVE     %4d in corpus, %d linked to a CWE, %d with no mapping"
          % (n_cve, linked, orphan))

    kinds, rels = summarize(g)
    print("\nGraph: %d nodes, %d edges" % (g.number_of_nodes(), g.number_of_edges()))
    print("  nodes    " + ", ".join("%s=%d" % kv for kv in sorted(kinds.items())))
    print("  relations " + ", ".join("%s=%d" % kv for kv in sorted(rels.items())))

    data = nx.node_link_data(g, edges="links")
    data["meta"] = {
        "nodes": g.number_of_nodes(),
        "edges": g.number_of_edges(),
        "kinds": kinds,
        "relations": rels,
        "sources": ["CWE-1000", "CAPEC-3000", "ATT&CK enterprise", "NVD API 2.0"],
    }
    with io.open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"))
    print("\nwrote %s (%.1f MB)"
          % (os.path.relpath(OUT_JSON, ROOT), os.path.getsize(OUT_JSON) / 1e6))

    write_cypher(g, OUT_CYPHER)
    print("wrote %s (%.1f MB)"
          % (os.path.relpath(OUT_CYPHER, ROOT), os.path.getsize(OUT_CYPHER) / 1e6))

    if args.stats:
        print("\nReachability from corpus CVEs:")
        reach = 0
        for node, attrs in g.nodes(data=True):
            if attrs.get("kind") != "cve":
                continue
            techniques = set()
            for cwe in g.successors(node):
                for capec in g.predecessors(cwe):
                    if g.nodes[capec].get("kind") != "capec":
                        continue
                    for t in g.successors(capec):
                        if g.nodes[t].get("kind") == "attack":
                            techniques.add(t)
            if techniques:
                reach += 1
                print("  %-18s -> %2d ATT&CK techniques" % (node, len(techniques)))
        print("  %d of %d CVEs reach at least one technique" % (reach, n_cve))

    return 0


if __name__ == "__main__":
    sys.exit(main())
