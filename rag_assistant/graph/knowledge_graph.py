"""Query layer over the CVE -> CWE -> CAPEC -> ATT&CK knowledge graph.

Loads the graph built by scripts/build_knowledge_graph.py and answers the
questions the application actually asks of it:

    chain(cve)        what weakness, attack patterns and adversary techniques
                      does this finding lead to
    context_for(cves) that same walk rendered as prompt text for the RAG stage
    neighborhood(id)  a bounded subgraph for the UI to draw
    search(term)      find a node by identifier or name

Everything is read-only after load, so a single process-wide instance is
shared. Loading is lazy and failure is non-fatal: the graph is an enrichment,
and a missing or corrupt graph file must degrade the answer rather than break
the request. That is the same rule the enrichment sources follow.
"""
import io
import json
import logging
import os
import threading
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..",
    "dataset", "knowledge_graph.json",
)

# A CVE with a common weakness such as CWE-79 can reach several hundred
# techniques. That is true but useless in a prompt, and it would crowd out the
# retrieved CVE text that the answer is supposed to be grounded in.
MAX_PATTERNS = 6
MAX_TECHNIQUES = 8


class KnowledgeGraph:
    """In-memory view of the MITRE join.

    Held as plain adjacency dicts rather than a NetworkX object: the queries
    below are all one- or two-hop walks, and this keeps the runtime free of a
    dependency that the API process would otherwise need only for lookups.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = os.path.abspath(path or _DEFAULT_PATH)
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.out: Dict[str, List[tuple]] = {}
        self.inc: Dict[str, List[tuple]] = {}
        self.meta: Dict[str, Any] = {}
        self.loaded = False
        self.error: Optional[str] = None

    def load(self) -> bool:
        if self.loaded or self.error:
            return self.loaded
        if not os.path.exists(self.path):
            self.error = (
                "knowledge graph not built. Run: python "
                "scripts/fetch_datasets.py && python scripts/build_knowledge_graph.py"
            )
            logger.warning(self.error)
            return False
        try:
            with io.open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            for node in data.get("nodes", []):
                self.nodes[node["id"]] = node
            for link in data.get("links", []):
                src, dst = link["source"], link["target"]
                rel = link.get("relation", "RELATED")
                self.out.setdefault(src, []).append((dst, rel))
                self.inc.setdefault(dst, []).append((src, rel))
            self.meta = data.get("meta", {})
            self.loaded = True
            logger.info("knowledge graph loaded: %d nodes, %d edges",
                        len(self.nodes), sum(len(v) for v in self.out.values()))
        except (ValueError, KeyError, OSError) as exc:
            self.error = "failed to load knowledge graph: %s" % exc
            logger.error(self.error)
        return self.loaded

    # -- helpers ---------------------------------------------------------

    def _kind(self, node_id: str) -> str:
        return (self.nodes.get(node_id) or {}).get("kind", "")

    def _succ(self, node_id: str, relation: str = None, kind: str = None):
        for dst, rel in self.out.get(node_id, []):
            if relation and rel != relation:
                continue
            if kind and self._kind(dst) != kind:
                continue
            yield dst

    def _pred(self, node_id: str, relation: str = None, kind: str = None):
        for src, rel in self.inc.get(node_id, []):
            if relation and rel != relation:
                continue
            if kind and self._kind(src) != kind:
                continue
            yield src

    def node(self, node_id: str) -> Optional[Dict[str, Any]]:
        self.load()
        return self.nodes.get(node_id)

    # -- queries ---------------------------------------------------------

    def chain(self, cve_id: str) -> Dict[str, Any]:
        """Walk a CVE out to the adversary techniques it enables.

        CAPEC points *at* the weakness it exploits, so the CWE-to-pattern step
        is an incoming edge, not an outgoing one. Getting that direction wrong
        yields an empty result rather than an error, which is why it is stated
        here explicitly.
        """
        self.load()
        result = {
            "cve": cve_id,
            "found": cve_id in self.nodes,
            "weaknesses": [],
            "patterns": [],
            "techniques": [],
            "tactics": [],
        }
        if not result["found"]:
            return result

        seen_patterns, seen_techniques = [], []
        for cwe in self._succ(cve_id, "EXPLOITS", "cwe"):
            node = self.nodes[cwe]
            result["weaknesses"].append({
                "id": cwe,
                "name": node.get("name", ""),
                "description": node.get("description", ""),
                "mitigations": node.get("mitigations", ""),
            })
            for capec in self._pred(cwe, "TARGETS", "capec"):
                if capec in seen_patterns:
                    continue
                seen_patterns.append(capec)
                for tech in self._succ(capec, "MAPS_TO", "attack"):
                    if tech not in seen_techniques:
                        seen_techniques.append(tech)

        # Rank by severity where CAPEC states one, so truncation keeps the
        # patterns an analyst would look at first.
        order = {"Very High": 0, "High": 1, "Medium": 2, "Low": 3, "Very Low": 4}
        seen_patterns.sort(key=lambda p: order.get(
            self.nodes[p].get("severity", ""), 9))

        for capec in seen_patterns[:MAX_PATTERNS]:
            node = self.nodes[capec]
            result["patterns"].append({
                "id": capec,
                "name": node.get("name", ""),
                "severity": node.get("severity", ""),
                "likelihood": node.get("likelihood", ""),
                "description": node.get("description", ""),
                "prerequisites": node.get("prerequisites", ""),
            })

        tactics = []
        for tech in seen_techniques[:MAX_TECHNIQUES]:
            node = self.nodes[tech]
            result["techniques"].append({
                "id": tech,
                "name": node.get("name", ""),
                "tactics": node.get("tactics", []),
                "url": node.get("url", ""),
            })
            for t in node.get("tactics", []):
                if t not in tactics:
                    tactics.append(t)
        result["tactics"] = tactics
        result["truncated"] = {
            "patterns": max(0, len(seen_patterns) - MAX_PATTERNS),
            "techniques": max(0, len(seen_techniques) - MAX_TECHNIQUES),
        }
        return result

    def context_for(self, cve_ids: Iterable[str]) -> str:
        """Render the walk as prompt text.

        Returned text is labelled as MITRE-derived and structural. The
        generation prompt treats it as evidence like any retrieved document,
        so it has to be as attributable as one -- every line here traces to a
        published MITRE cross-reference, and the grounding verifier checks the
        identifiers in it the same way it checks retrieved CVE text.
        """
        self.load()
        blocks = []
        for cve_id in cve_ids:
            chain = self.chain(cve_id)
            if not chain["found"] or not chain["weaknesses"]:
                continue
            lines = ["%s structural context (MITRE):" % cve_id]
            for w in chain["weaknesses"]:
                lines.append("  Weakness %s: %s" % (w["id"], w["name"]))
            if chain["patterns"]:
                lines.append("  Attack patterns that exploit this weakness class:")
                for p in chain["patterns"]:
                    sev = " [%s severity]" % p["severity"] if p["severity"] else ""
                    lines.append("    %s: %s%s" % (p["id"], p["name"], sev))
            if chain["techniques"]:
                lines.append("  Corresponding ATT&CK techniques:")
                for t in chain["techniques"]:
                    tac = ", ".join(t["tactics"])
                    lines.append("    %s: %s%s"
                                 % (t["id"], t["name"], " (%s)" % tac if tac else ""))
            blocks.append("\n".join(lines))
        return "\n\n".join(blocks)

    def neighborhood(self, node_id: str, depth: int = 2, limit: int = 120):
        """Bounded subgraph around a node, for drawing.

        Breadth-first with a hard node cap. Hub weaknesses such as CWE-20 have
        very high degree, and an uncapped two-hop expansion around one returns
        a graph no viewer can render or read.
        """
        self.load()
        if node_id not in self.nodes:
            return {"nodes": [], "links": [], "found": False}

        seen = {node_id: 0}
        frontier = [node_id]
        for _ in range(max(0, depth)):
            nxt = []
            for current in frontier:
                neighbours = [d for d, _ in self.out.get(current, [])] + \
                             [s for s, _ in self.inc.get(current, [])]
                for other in neighbours:
                    if other not in seen and len(seen) < limit:
                        seen[other] = seen[current] + 1
                        nxt.append(other)
            frontier = nxt
            if not frontier:
                break

        nodes = [dict(self.nodes[n], distance=seen[n]) for n in seen if n in self.nodes]
        links = []
        for src in seen:
            for dst, rel in self.out.get(src, []):
                if dst in seen:
                    links.append({"source": src, "target": dst, "relation": rel})
        return {
            "nodes": nodes,
            "links": links,
            "found": True,
            "root": node_id,
            "truncated": len(seen) >= limit,
        }

    def search(self, term: str, limit: int = 25) -> List[Dict[str, Any]]:
        self.load()
        term = (term or "").strip().lower()
        if not term:
            return []
        exact, partial = [], []
        for node_id, node in self.nodes.items():
            lid = node_id.lower()
            if lid == term:
                exact.append(node)
            elif term in lid or term in (node.get("name", "") or "").lower():
                partial.append(node)
            if len(partial) > limit * 4:
                break
        return (exact + partial)[:limit]

    def stats(self) -> Dict[str, Any]:
        self.load()
        return {
            "loaded": self.loaded,
            "error": self.error,
            "path": self.path,
            "nodes": len(self.nodes),
            "edges": sum(len(v) for v in self.out.values()),
            "meta": self.meta,
        }


_instance: Optional[KnowledgeGraph] = None
_lock = threading.Lock()


def get_knowledge_graph() -> KnowledgeGraph:
    """Process-wide instance.

    Double-checked under a lock: FastAPI serves requests from a thread pool,
    and two concurrent first-requests would otherwise each parse the file.
    """
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = KnowledgeGraph()
    return _instance
