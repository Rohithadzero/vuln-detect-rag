"""Knowledge graph endpoints.

Serves the CVE -> CWE -> CAPEC -> ATT&CK join built by
scripts/build_knowledge_graph.py. Read-only: the graph is a published
cross-reference, not user data, and nothing here mutates it.

The graph may legitimately be absent -- it is an optional enrichment built
from downloaded datasets. Endpoints therefore report its absence as a state
rather than raising, so a deployment that never ran the build script still
serves a working UI.
"""
import logging
import os
import sys

from fastapi import APIRouter, HTTPException, Query

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from rag_assistant.graph import get_knowledge_graph

logger = logging.getLogger("vulndetect")
router = APIRouter()


@router.get("/graph/stats")
async def graph_stats():
    """Graph size and whether it loaded, for the dashboard and diagnostics."""
    return get_knowledge_graph().stats()


@router.get("/graph/chain/{cve_id}")
async def graph_chain(cve_id: str):
    """Walk one CVE out to the ATT&CK techniques it enables.

    Returns found=false rather than 404 when the CVE is outside the corpus:
    the caller wants to know the walk produced nothing, and a 404 here reads
    as a broken endpoint rather than an empty result.
    """
    graph = get_knowledge_graph()
    if not graph.load():
        raise HTTPException(status_code=503, detail=graph.error)
    return graph.chain(cve_id.strip().upper())


@router.get("/graph/node/{node_id}")
async def graph_node(node_id: str):
    graph = get_knowledge_graph()
    if not graph.load():
        raise HTTPException(status_code=503, detail=graph.error)
    node = graph.node(node_id.strip().upper())
    if node is None:
        raise HTTPException(status_code=404, detail="no such node: %s" % node_id)
    outgoing = [{"id": d, "relation": r, "name": (graph.node(d) or {}).get("name", ""),
                 "kind": (graph.node(d) or {}).get("kind", "")}
                for d, r in graph.out.get(node_id.strip().upper(), [])]
    incoming = [{"id": s, "relation": r, "name": (graph.node(s) or {}).get("name", ""),
                 "kind": (graph.node(s) or {}).get("kind", "")}
                for s, r in graph.inc.get(node_id.strip().upper(), [])]
    return {"node": node, "outgoing": outgoing[:200], "incoming": incoming[:200]}


@router.get("/graph/neighborhood/{node_id}")
async def graph_neighborhood(
    node_id: str,
    depth: int = Query(2, ge=1, le=3),
    limit: int = Query(120, ge=10, le=400),
):
    """Bounded subgraph for drawing.

    depth and limit are capped by the query model rather than trusted: a
    three-hop uncapped expansion from a hub weakness reaches most of the graph
    and would serve megabytes to a browser that cannot draw it.
    """
    graph = get_knowledge_graph()
    if not graph.load():
        raise HTTPException(status_code=503, detail=graph.error)
    return graph.neighborhood(node_id.strip().upper(), depth=depth, limit=limit)


@router.get("/graph/search")
async def graph_search(q: str = Query(..., min_length=1, max_length=100),
                       limit: int = Query(25, ge=1, le=100)):
    graph = get_knowledge_graph()
    if not graph.load():
        raise HTTPException(status_code=503, detail=graph.error)
    return {"query": q, "results": graph.search(q, limit=limit)}
