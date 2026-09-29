"""Query/response types and tunables for the RAG pipeline."""

import os
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

#: Matches a CVE identifier anywhere in free text.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

#: Documents scoring below this cosine similarity are treated as noise rather
#: than context. Without a floor, an empty-ish store still returns its five
#: least-bad documents and the model is invited to treat them as evidence.
DEFAULT_SCORE_THRESHOLD = float(os.getenv('RAG_SCORE_THRESHOLD', '0.25'))

#: How many documents to pull before diversity filtering trims to top_k.
OVERFETCH_MULTIPLIER = int(os.getenv('RAG_OVERFETCH', '4'))

#: Character budget for retrieved context in the prompt.
CONTEXT_CHAR_BUDGET = int(os.getenv('RAG_CONTEXT_BUDGET', '6000'))

#: Character budget for conversation history in the prompt.
HISTORY_CHAR_BUDGET = int(os.getenv('RAG_HISTORY_BUDGET', '2000'))

#: Verify the finished answer's claims against the retrieved text.
VERIFY_ANSWERS = os.getenv('RAG_VERIFY', '1').lower() not in ('0', 'false', 'no')

#: Spend one extra LLM call rewriting an answer that asserted facts the context
#: does not contain. Off makes unsupported claims visible but leaves them in
#: place; on removes them at the cost of one small request.
REPAIR_ANSWERS = os.getenv('RAG_VERIFY_REPAIR', '1').lower() not in ('0', 'false', 'no')

#: Append MITRE knowledge-graph structure (CWE, CAPEC, ATT&CK) for the CVEs
#: that retrieval returned. Off falls back to retrieved text alone.
GRAPH_CONTEXT = os.getenv('RAG_GRAPH_CONTEXT', '1').lower() not in ('0', 'false', 'no')

#: Character budget for the graph block. Kept well under the retrieval budget
#: on purpose: this is supporting structure, and it must not displace the CVE
#: text that the answer is meant to be grounded in.
GRAPH_CHAR_BUDGET = int(os.getenv('RAG_GRAPH_BUDGET', '1500'))


@dataclass
class RAGQuery:
    """Query for RAG system."""
    question: str
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    filters: Optional[Dict[str, Any]] = None
    top_k: int = 5
    include_sources: bool = True
    conversation_history: bool = True
    #: Restrict retrieval to one corpus: "cve_database", "scan_result", or
    #: None for both.
    source_type: Optional[str] = None
    score_threshold: float = DEFAULT_SCORE_THRESHOLD


@dataclass
class RAGResponse:
    """Response from RAG system."""
    answer: str
    sources: List[Dict[str, Any]]
    session_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    #: True when retrieval returned usable context. When False the answer is
    #: an explicit refusal rather than an ungrounded guess.
    grounded: bool = True
