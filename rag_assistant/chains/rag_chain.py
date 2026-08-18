"""RAG chain implementation for vulnerability analysis."""

import os
import re
import time
import logging
from typing import List, Dict, Any, Optional, Tuple, Iterator
from dataclasses import dataclass, field

from ..vectorstore.vector_store import get_vector_store, BaseVectorStore, Document, SearchResult
from ..embeddings.embedding_service import get_embedding_service, EmbeddingService
from ..memory.conversation_memory import get_conversation_memory, ConversationMemory
from ..llm_config import get_llm_client, BaseLLMClient

logger = logging.getLogger(__name__)

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


class RAGPipeline:
    """Main RAG pipeline for vulnerability analysis."""

    SYSTEM_PROMPT = """You are a cybersecurity expert assistant specializing in vulnerability analysis, remediation guidance, and exploit identification. You help security professionals understand and address security vulnerabilities.

GROUNDING RULES (these override everything else):
1. Answer ONLY from the numbered context documents provided below.
2. Cite the document you used inline, like [Doc 2], after each specific claim.
3. If the context does not contain the answer, say so plainly and state what is missing. Never fill the gap from memory.
4. Never invent CVE IDs, CVSS scores, version numbers, or patch levels. If a value is not in the context, say it is not available.
5. When the context and the question disagree (for example a CVE ID that is absent from the context), point that out rather than guessing.

ANSWER FORMAT:
- Lead with a direct one or two sentence answer.
- Then give the technical detail: affected products and versions, CVSS score and severity, and attack vector.
- Then give concrete remediation steps, most important first.
- Prioritize CRITICAL and HIGH severity findings.
- Be precise and technical. No filler, no restating the question."""

    #: Appended when retrieval found nothing, to make refusal the easy path.
    NO_CONTEXT_INSTRUCTION = """No relevant documents were retrieved from the vulnerability database for this question.

Tell the user plainly that the knowledge base has no matching entry, and suggest what they could do next (run a scan against the target, seed the CVE database, or rephrase with a specific CVE ID). Do NOT answer from prior knowledge and do NOT invent details."""

    def __init__(self, vector_store: Optional[BaseVectorStore] = None,
                 embedding_service: Optional[EmbeddingService] = None,
                 llm_client: Optional[BaseLLMClient] = None,
                 conversation_memory: Optional[ConversationMemory] = None):
        """Initialize RAG pipeline.

        Args:
            vector_store: Vector store instance
            embedding_service: Embedding service instance
            llm_client: LLM client instance
            conversation_memory: Conversation memory instance
        """
        self.vector_store = vector_store or get_vector_store()
        self.embedding_service = embedding_service or get_embedding_service()
        self._llm_client = llm_client
        self.conversation_memory = conversation_memory or get_conversation_memory()

        self._initialized = False

    @property
    def llm_client(self) -> BaseLLMClient:
        """Lazily build the LLM client.

        Deferred so that importing or indexing does not require a running LLM;
        eager construction made the API module fail to import whenever Ollama
        was not up.
        """
        if self._llm_client is None:
            self._llm_client = get_llm_client()
        return self._llm_client

    def initialize(self) -> bool:
        """Initialize RAG pipeline components.

        Returns:
            True if initialization successful
        """
        try:
            doc_count = self.vector_store.count()
            logger.info(
                f"RAG pipeline initialized with {doc_count} documents "
                f"in collection '{self.vector_store.collection_name}'"
            )
            if doc_count == 0:
                logger.warning(
                    "Vector store is EMPTY. Run: python scripts/seed_cve_data.py"
                )
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"Failed to initialize RAG pipeline: {e}")
            return False

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def add_documents(self, documents: List[Dict[str, Any]],
                      chunk: bool = True) -> int:
        """Add documents to the RAG system.

        Long documents are split into overlapping chunks before embedding.
        A single vector cannot faithfully represent a long, multi-topic text,
        so chunking materially improves retrieval precision. Short documents
        (most CVE records) pass through as a single chunk.

        Args:
            documents: List of document dictionaries with content and metadata
            chunk: Whether to split long documents before embedding

        Returns:
            Number of chunks added
        """
        prepared: List[Tuple[str, str, Dict[str, Any]]] = []

        for doc_data in documents:
            content = (doc_data.get('content') or '').strip()
            if not content:
                continue

            base_id = doc_data.get('id') or self._generate_doc_id(content)
            metadata = dict(doc_data.get('metadata') or {})

            pieces = (
                self.embedding_service.chunk_text(content) if chunk else [content]
            )
            total = len(pieces)

            for index, piece in enumerate(pieces):
                piece_metadata = dict(metadata)
                piece_metadata.setdefault('source_type', 'unknown')
                piece_metadata.setdefault('title', base_id)
                piece_metadata['chunk_index'] = index
                piece_metadata['chunk_count'] = total
                piece_metadata['parent_id'] = base_id

                piece_id = base_id if total == 1 else f"{base_id}::chunk{index}"
                prepared.append((piece_id, piece, piece_metadata))

        if not prepared:
            return 0

        # Batch-embed everything at once — far faster than one call per doc.
        try:
            embeddings = self.embedding_service.embed_batch(
                [text for _, text, _ in prepared]
            )
        except Exception as e:
            logger.error(f"Failed to embed documents: {e}")
            return 0

        vector_docs = [
            Document(id=doc_id, content=text, metadata=meta, embedding=embedding)
            for (doc_id, text, meta), embedding in zip(prepared, embeddings)
        ]

        if not self.vector_store.add_documents(vector_docs):
            return 0

        logger.info(
            f"Added {len(vector_docs)} chunks from {len(documents)} documents"
        )
        return len(vector_docs)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def retrieve(self, rag_query: RAGQuery) -> List[SearchResult]:
        """Retrieve context for a query.

        Hybrid strategy, because pure vector search is weak on identifiers:
        an embedding of "CVE-2021-44228" is nearly indistinguishable from any
        other CVE ID, so an exact metadata lookup runs alongside the semantic
        search and its hits are pinned to the front.
        """
        filters = dict(rag_query.filters or {})
        if rag_query.source_type:
            filters['source_type'] = rag_query.source_type

        results: List[SearchResult] = []
        seen_ids: set = set()

        # 1. Exact CVE-ID lookup for any identifier mentioned in the question.
        for cve_id in self._extract_cve_ids(rag_query.question):
            exact_filter = dict(filters)
            exact_filter['cve_id'] = cve_id
            for hit in self._search(rag_query, exact_filter, top_k=rag_query.top_k):
                if hit.document.id not in seen_ids:
                    seen_ids.add(hit.document.id)
                    # Exact identifier matches are authoritative for this query.
                    hit.score = max(hit.score, 0.99)
                    results.append(hit)

        # 2. Semantic search, over-fetched so diversity filtering has room.
        semantic = self._search(
            rag_query, filters, top_k=rag_query.top_k * OVERFETCH_MULTIPLIER
        )
        for hit in semantic:
            if hit.document.id not in seen_ids:
                seen_ids.add(hit.document.id)
                results.append(hit)

        # 3. Drop weak matches, then de-duplicate near-identical chunks.
        kept = [r for r in results if r.score >= rag_query.score_threshold]
        if not kept and results:
            best = max(r.score for r in results)
            logger.info(
                "All %d retrieved documents scored below threshold %.2f "
                "(best %.2f); treating query as ungrounded",
                len(results), rag_query.score_threshold, best,
            )

        deduped = self._deduplicate(kept)
        return deduped[:rag_query.top_k]

    def _search(self, rag_query: RAGQuery, filters: Dict[str, Any],
                top_k: int) -> List[SearchResult]:
        """Run one vector-store search, tolerating backend errors."""
        try:
            query_embedding = self.embedding_service.embed(rag_query.question)
            return self.vector_store.search(
                query_embedding=query_embedding,
                top_k=top_k,
                filter_metadata=filters or None,
            )
        except Exception as e:
            logger.error(f"Retrieval failed: {e}")
            return []

    @staticmethod
    def _extract_cve_ids(text: str) -> List[str]:
        """Pull CVE identifiers out of a question, normalized to upper case."""
        return list(dict.fromkeys(m.upper() for m in CVE_PATTERN.findall(text or "")))

    @staticmethod
    def _deduplicate(results: List[SearchResult]) -> List[SearchResult]:
        """Collapse repeated coverage of the same vulnerability.

        Several chunks of one CVE crowd out other findings, which is the
        classic failure of naive top-k: five slices of one document instead of
        five distinct documents. Keeps the best-scoring chunk per CVE (or per
        parent document when there is no CVE ID).
        """
        best_by_key: Dict[str, SearchResult] = {}
        ordered: List[SearchResult] = []

        for result in sorted(results, key=lambda r: r.score, reverse=True):
            metadata = result.metadata or {}
            key = (
                str(metadata.get('cve_id'))
                if metadata.get('cve_id')
                else str(metadata.get('parent_id') or result.document.id)
            )
            if key not in best_by_key:
                best_by_key[key] = result
                ordered.append(result)

        return ordered

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def query(self, rag_query: RAGQuery) -> RAGResponse:
        """Process RAG query.

        Args:
            rag_query: RAG query object

        Returns:
            RAG response with answer and sources
        """
        if not self._initialized:
            self.initialize()

        session_id = rag_query.session_id or self._generate_session_id()
        started = time.perf_counter()

        try:
            retrieval_started = time.perf_counter()
            search_results = self.retrieve(rag_query)
            retrieval_ms = round((time.perf_counter() - retrieval_started) * 1000, 1)

            grounded = bool(search_results)
            context = self._build_context(search_results)

            history = []
            if rag_query.conversation_history:
                history = self.conversation_memory.get_conversation_history(
                    session_id, limit=6
                )

            prompt = self._build_prompt(rag_query.question, context, history, grounded)

            llm_result = self.llm_client.generate_detailed(
                prompt, system=self.SYSTEM_PROMPT
            )
            if llm_result.error:
                raise RuntimeError(llm_result.error)
            answer = llm_result.text

            self.conversation_memory.add_message(
                session_id=session_id,
                role='user',
                content=rag_query.question
            )
            self.conversation_memory.add_message(
                session_id=session_id,
                role='assistant',
                content=answer,
                sources=[s.metadata for s in search_results]
            )

            sources = []
            if rag_query.include_sources:
                sources = [
                    {
                        'content': self._truncate(r.document.content, 300),
                        'score': round(r.score, 4),
                        'metadata': r.metadata,
                    }
                    for r in search_results
                ]

            return RAGResponse(
                answer=answer,
                sources=sources,
                session_id=session_id,
                grounded=grounded,
                metadata={
                    'documents_retrieved': len(search_results),
                    'grounded': grounded,
                    'retrieval_ms': retrieval_ms,
                    'generation_ms': llm_result.latency_ms,
                    'total_ms': round((time.perf_counter() - started) * 1000, 1),
                    'prompt_tokens': llm_result.prompt_tokens,
                    'completion_tokens': llm_result.completion_tokens,
                    'llm_provider': llm_result.provider,
                    'llm_model': llm_result.model,
                    'top_score': round(search_results[0].score, 4) if search_results else 0.0,
                }
            )

        except Exception as e:
            logger.error(f"RAG query failed: {e}")
            return RAGResponse(
                answer=(
                    "I could not complete this query because the language model "
                    f"is unavailable: {e}"
                ),
                sources=[],
                session_id=session_id,
                grounded=False,
                metadata={
                    'error': str(e),
                    'total_ms': round((time.perf_counter() - started) * 1000, 1),
                },
            )

    def stream_query(self, rag_query: RAGQuery) -> Iterator[str]:
        """Stream an answer token by token.

        Retrieval still runs to completion first; only generation streams.
        """
        if not self._initialized:
            self.initialize()

        search_results = self.retrieve(rag_query)
        context = self._build_context(search_results)
        history = []
        if rag_query.conversation_history and rag_query.session_id:
            history = self.conversation_memory.get_conversation_history(
                rag_query.session_id, limit=6
            )
        prompt = self._build_prompt(
            rag_query.question, context, history, bool(search_results)
        )
        yield from self.llm_client.stream(prompt, system=self.SYSTEM_PROMPT)

    def query_simple(self, question: str, session_id: Optional[str] = None, **kwargs) -> str:
        """Simple query interface.

        Args:
            question: User question
            session_id: Optional session ID
            **kwargs: Additional query parameters

        Returns:
            Answer string
        """
        rag_query = RAGQuery(question=question, session_id=session_id, **kwargs)
        response = self.query(rag_query)
        return response.answer

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_context(self, search_results: List[SearchResult]) -> str:
        """Build context string from search results.

        Args:
            search_results: Search results

        Returns:
            Context string
        """
        if not search_results:
            return ""

        parts = ["=== RETRIEVED CONTEXT ==="]
        budget = CONTEXT_CHAR_BUDGET

        for i, result in enumerate(search_results, 1):
            metadata = result.document.metadata or {}
            source_type = metadata.get('source_type', 'unknown')
            title = metadata.get('title') or metadata.get('cve_id') or 'Untitled'

            header = [f"\n[Doc {i}] {title}"]
            header.append(f"Source: {self._describe_source(source_type, metadata)}")
            header.append(f"Relevance: {result.score:.2f}")

            if metadata.get('cve_id'):
                header.append(f"CVE ID: {metadata['cve_id']}")
            if metadata.get('cvss_score') not in (None, ''):
                header.append(
                    f"CVSS: {metadata['cvss_score']} ({metadata.get('severity', 'UNKNOWN')})"
                )
            if metadata.get('exploit_available'):
                header.append("Known public exploit: yes")
            if metadata.get('affected_host'):
                location = str(metadata['affected_host'])
                if metadata.get('affected_port'):
                    location += f":{metadata['affected_port']}"
                header.append(f"Observed on: {location}")
            if metadata.get('scan_id'):
                header.append(f"From scan: #{metadata['scan_id']}")

            body = result.document.content
            block = "\n".join(header) + f"\n{body}\n"

            if len(block) > budget:
                block = block[:max(budget, 0)] + "\n[...truncated...]\n"
            parts.append(block)
            budget -= len(block)
            if budget <= 0:
                logger.debug("Context budget exhausted after %d documents", i)
                break

        return "\n".join(parts)

    @staticmethod
    def _describe_source(source_type: str, metadata: Dict[str, Any]) -> str:
        """Human-readable provenance, so the model can weight evidence."""
        if source_type == 'scan_result':
            scanner = metadata.get('source_scanner', 'unknown scanner')
            simulated = metadata.get('simulated')
            suffix = " (SIMULATED DATA, not a live scan)" if simulated else ""
            return f"live scan finding from {scanner}{suffix}"
        if source_type == 'cve_database':
            return f"CVE database entry ({metadata.get('source', 'NVD')})"
        return source_type or 'unknown'

    def _build_prompt(self, question: str, context: str,
                      history: List[Dict[str, Any]], grounded: bool) -> str:
        """Assemble the user-turn prompt.

        The system persona is passed separately via the chat API's system role
        rather than being concatenated here, which keeps it outside the text
        the model treats as retrieved evidence.
        """
        sections: List[str] = []

        if grounded and context:
            sections.append(context)
        else:
            sections.append(self.NO_CONTEXT_INSTRUCTION)

        history_block = self._format_history(history)
        if history_block:
            sections.append(history_block)

        sections.append(f"=== QUESTION ===\n{question}")

        if grounded:
            sections.append(
                "Answer using only the context above, citing documents as [Doc N]."
            )

        return "\n\n".join(sections)

    @staticmethod
    def _format_history(history: List[Dict[str, Any]]) -> str:
        """Render recent turns within a character budget.

        Earlier code cut every message to 200 characters, which reliably
        severed the assistant's own prior answer mid-sentence and fed the model
        a corrupted transcript. Whole recent turns are kept instead, dropping
        older ones once the budget is spent.
        """
        if not history:
            return ""

        lines: List[str] = []
        budget = HISTORY_CHAR_BUDGET

        for message in reversed(history):
            role = str(message.get('role', 'unknown')).capitalize()
            content = str(message.get('content', '')).strip()
            if not content:
                continue
            entry = f"{role}: {content}"
            if len(entry) > budget:
                break
            lines.append(entry)
            budget -= len(entry)

        if not lines:
            return ""

        return "=== CONVERSATION HISTORY ===\n" + "\n".join(reversed(lines))

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        """Truncate for display, marking that truncation happened."""
        text = text or ""
        return text if len(text) <= limit else text[:limit].rstrip() + "..."

    def _generate_doc_id(self, content: str) -> str:
        """Generate document ID from content."""
        import hashlib
        return hashlib.md5(content.encode()).hexdigest()[:16]

    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        import uuid
        return str(uuid.uuid4())

    def get_stats(self) -> Dict[str, Any]:
        """Get RAG system statistics.

        Returns:
            Statistics dictionary
        """
        stats: Dict[str, Any] = {
            'total_documents': self.vector_store.count(),
            'collection': self.vector_store.collection_name,
            'active_sessions': len(self.conversation_memory.get_all_sessions()),
            'embedding_provider': self.embedding_service.provider,
            'embedding_model': self.embedding_service.model,
        }
        # Reported separately so a missing LLM does not blank out store stats.
        try:
            stats['llm_provider'] = self.llm_client.config.provider
            stats['llm_model'] = self.llm_client.config.model
        except Exception as e:
            stats['llm_provider'] = 'unavailable'
            stats['llm_error'] = str(e)
        return stats


class VulnerabilityRAGPipeline(RAGPipeline):
    """Specialized RAG pipeline for vulnerability analysis."""

    @classmethod
    def create_remediation_chain(cls) -> 'VulnerabilityRAGPipeline':
        """Create pipeline optimized for remediation queries."""
        pipeline = cls()
        pipeline.SYSTEM_PROMPT = """You are a vulnerability remediation specialist.

GROUNDING RULES (these override everything else):
1. Base every recommendation on the numbered context documents below, citing them as [Doc N].
2. Never invent patch versions, configuration keys, or vendor advisories. If the context lacks a fix, say so.
3. If the context is empty, say the knowledge base has no entry rather than guessing.

Focus on:
1. Step-by-step remediation guidance
2. Prioritizing by severity and exploitability
3. Compensating controls when an immediate fix is not possible
4. Configuration examples where the context supports them
5. Dependencies and prerequisites for each fix

For each recommendation: explain the vulnerability and its risk, give specific steps, and note any operational impact or side effects."""
        return pipeline

    @classmethod
    def create_exploit_analysis_chain(cls) -> 'VulnerabilityRAGPipeline':
        """Create pipeline optimized for exploit analysis."""
        pipeline = cls()
        pipeline.SYSTEM_PROMPT = """You are an exploit analysis specialist supporting authorized defensive security work.

GROUNDING RULES (these override everything else):
1. Base your analysis on the numbered context documents below, citing them as [Doc N].
2. Never invent CVE IDs, affected versions, or exploit availability. If the context lacks it, say so.
3. If the context is empty, say the knowledge base has no entry rather than guessing.

Focus on:
1. How the vulnerability works technically
2. Affected systems and versions
3. Attack vectors and preconditions
4. Exploitability and whether public exploit code exists
5. Detection and mitigation strategies

Explain mechanisms at a conceptual level and prioritize detection signatures and defensive guidance. Do not produce working exploit code."""
        return pipeline

    @classmethod
    def create_attack_path_chain(cls) -> 'VulnerabilityRAGPipeline':
        """Create pipeline optimized for attack path analysis."""
        pipeline = cls()
        pipeline.SYSTEM_PROMPT = """You are a network attack path analyst.

GROUNDING RULES (these override everything else):
1. Base every hop you describe on the numbered context documents below, citing them as [Doc N].
2. Never invent hosts, services, or vulnerabilities that are not in the context.
3. If the context is empty, say the knowledge base has no entry rather than guessing.

Focus on:
1. Modeling plausible attack chains from the observed findings
2. Identifying pivot points and lateral movement opportunities
3. Assessing privilege escalation paths
4. Evaluating network segmentation effectiveness
5. Recommending controls that break the chain

For each path: map source to target, identify intermediate hops, analyze service relationships, and suggest the single most effective disruption point."""
        return pipeline


#: Pipelines are cached per type. Each construction loads an embedding model and
#: opens the vector store, so rebuilding one per request was pure overhead.
_PIPELINE_CACHE: Dict[str, RAGPipeline] = {}


def get_rag_pipeline(pipeline_type: str = 'default') -> RAGPipeline:
    """Get configured RAG pipeline.

    Args:
        pipeline_type: Type of pipeline (default, remediation, exploit, attack_path)

    Returns:
        Configured RAG pipeline
    """
    pipeline_type = (pipeline_type or 'default').lower()

    if pipeline_type in _PIPELINE_CACHE:
        return _PIPELINE_CACHE[pipeline_type]

    builders = {
        'remediation': VulnerabilityRAGPipeline.create_remediation_chain,
        'exploit': VulnerabilityRAGPipeline.create_exploit_analysis_chain,
        'attack_path': VulnerabilityRAGPipeline.create_attack_path_chain,
    }

    if pipeline_type not in builders and pipeline_type != 'default':
        raise ValueError(
            f"Unknown pipeline type '{pipeline_type}'. "
            f"Valid: default, {', '.join(builders)}"
        )

    pipeline = builders[pipeline_type]() if pipeline_type in builders else RAGPipeline()

    # Specialized pipelines differ only by system prompt, so they can share the
    # default pipeline's loaded embedding model and vector store handle.
    if pipeline_type != 'default' and 'default' in _PIPELINE_CACHE:
        base = _PIPELINE_CACHE['default']
        pipeline.vector_store = base.vector_store
        pipeline.embedding_service = base.embedding_service
        pipeline.conversation_memory = base.conversation_memory

    _PIPELINE_CACHE[pipeline_type] = pipeline
    return pipeline


def available_pipelines() -> List[str]:
    """List the selectable pipeline types."""
    return ['default', 'remediation', 'exploit', 'attack_path']
