"""RAG Engine — now powered by the modular rag_assistant package.

Wraps the new modular RAG pipeline (llm_config, embeddings, vectorstore, chains, memory)
so the rest of the backend can keep using the same simple interface.
"""

import logging
import sys
import os

# Add project root to path so we can import rag_assistant
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from rag_assistant import (
    LLMFactory,
    get_llm_client,
    BaseLLMClient,
    LLMConfig,
    get_vector_store,
    BaseVectorStore,
    Document,
    SearchResult,
    VectorStoreFactory,
    get_embedding_service,
    EmbeddingService,
    EmbeddingCache,
    get_conversation_memory,
    ConversationMemory,
    RAGPipeline,
    RAGQuery,
    RAGResponse,
    VulnerabilityRAGPipeline,
    get_rag_pipeline,
)

from config import settings

logger = logging.getLogger("vulndetect")


class RAGEngine:
    """RAG pipeline for vulnerability Q&A using modular rag_assistant components.

    This wraps the modular RAG architecture:
      - llm_config.py      → Multi-provider LLM factory (Ollama, OpenAI, Groq, HuggingFace)
      - embeddings/        → Embedding service with caching
      - vectorstore/       → ChromaDB + FAISS vector store abstraction
      - chains/            → RAG chain with specialized pipelines
      - memory/            → In-memory + Redis conversation memory
    """

    def __init__(self):
        # Initialize modular components
        self._pipeline: RAGPipeline | None = None
        self._vector_store: BaseVectorStore | None = None
        self._embedding_service: EmbeddingService | None = None
        self._llm_client: BaseLLMClient | None = None
        self._conversation_memory: ConversationMemory | None = None

        # Publish the backend's configured collection and persistence path to
        # the standalone rag_assistant package, which reads them from the
        # environment. Without this the writer and the reader can select
        # different collections and retrieval silently returns nothing.
        os.environ.setdefault("CHROMA_COLLECTION", settings.CHROMA_COLLECTION)
        os.environ.setdefault("VECTOR_STORE_PATH", settings.CHROMA_PERSIST_DIR)

    def _ensure_pipeline(self) -> RAGPipeline:
        """Lazily initialize the RAG pipeline."""
        if self._pipeline is None:
            self._pipeline = get_rag_pipeline("default")
            self._pipeline.initialize()
        return self._pipeline

    @property
    def vector_store(self) -> BaseVectorStore:
        if self._vector_store is None:
            self._vector_store = get_vector_store(
                collection_name=settings.CHROMA_COLLECTION,
                persist_directory=settings.CHROMA_PERSIST_DIR,
            )
        return self._vector_store

    @property
    def embedding_service(self) -> EmbeddingService:
        if self._embedding_service is None:
            self._embedding_service = get_embedding_service()
        return self._embedding_service

    @property
    def llm_client(self) -> BaseLLMClient:
        if self._llm_client is None:
            self._llm_client = get_llm_client()
        return self._llm_client

    @property
    def conversation_memory(self) -> ConversationMemory:
        if self._conversation_memory is None:
            self._conversation_memory = get_conversation_memory()
        return self._conversation_memory

    # ------------------------------------------------------------------
    # Public API — same interface as the old rag_engine
    # ------------------------------------------------------------------

    @staticmethod
    def check_ollama_available() -> dict:
        """Check if Ollama is running and the configured model is available."""
        return LLMFactory.check_ollama_available()

    def index_cves(self, cve_entries: list[dict]) -> int:
        """Index CVE entries into the vector store.

        Documents are tagged ``source_type='cve_database'`` so retrieval can be
        scoped to the static knowledge base, and given a real title so the
        prompt context no longer renders every document as "Untitled".
        """
        if not cve_entries:
            return 0

        documents = []
        for entry in cve_entries:
            cve_id = entry.get("cve_id", "")
            description = entry.get("description", "")
            solution = entry.get("solution", "")
            severity = entry.get("severity", "LOW")
            cvss = entry.get("cvss_score", 0.0)

            # A self-describing body: the retrieved chunk has to stand alone in
            # the prompt, so the key facts are stated in the text itself rather
            # than living only in metadata.
            text = (
                f"{cve_id} ({severity}, CVSS {cvss})\n"
                f"Description: {description}\n"
                f"Remediation: {solution or 'No remediation recorded.'}"
            )

            metadata = {
                "cve_id": cve_id,
                "title": f"{cve_id} — {self._short_title(description)}",
                "source_type": "cve_database",
                "source": entry.get("source", "NVD"),
                "severity": severity,
                "cvss_score": cvss,
                "exploit_available": entry.get("exploit_available", False),
            }
            documents.append(
                {"content": text, "id": cve_id or None, "metadata": metadata}
            )

        pipeline = self._ensure_pipeline()
        added = pipeline.add_documents(documents)
        logger.info(f"Indexed {added} CVE chunks into vector store")
        return added

    def index_scan_results(self, scan_id: int, target: str, vulnerabilities: list) -> int:
        """Index the findings of a completed scan so the assistant can discuss them.

        Without this the assistant can only answer from the static CVE bundle
        and is blind to the scan the user just ran. Documents are tagged
        ``source_type='scan_result'`` so they stay distinguishable from — and
        filterable against — the CVE knowledge base.

        Args:
            scan_id: ID of the completed scan
            target: Scan target, embedded in the text for retrievability
            vulnerabilities: VulnerabilityDB rows (or any object exposing the
                same attributes)

        Returns:
            Number of chunks indexed
        """
        if not vulnerabilities:
            return 0

        # Re-indexing a scan replaces its previous documents rather than
        # accumulating duplicates alongside them.
        try:
            removed = self.vector_store.delete_where({"scan_id": scan_id})
            if removed:
                logger.info("Removed %d stale documents for scan %d", removed, scan_id)
        except Exception:
            logger.debug("No prior documents to remove for scan %d", scan_id)

        documents = []
        for vuln in vulnerabilities:
            raw_output = getattr(vuln, "raw_output", None) or {}
            simulated = raw_output.get("type") == "mock"
            cve_id = getattr(vuln, "cve_id", None)
            severity = getattr(vuln, "severity", "LOW")
            cvss = getattr(vuln, "cvss_score", 0.0)
            scanner = getattr(vuln, "source_scanner", "")
            host = getattr(vuln, "affected_host", "") or target
            port = getattr(vuln, "affected_port", None)
            service = getattr(vuln, "affected_service", None)
            description = getattr(vuln, "description", "")
            solution = getattr(vuln, "solution", "")

            location = f"{host}:{port}" if port else host
            label = cve_id or f"Finding {getattr(vuln, 'id', '?')}"

            text = (
                f"Scan #{scan_id} finding on target {target}: {label} "
                f"({severity}, CVSS {cvss})\n"
                f"Location: {location}"
                + (f" running {service}" if service else "")
                + f"\nReported by: {scanner}"
                + (" [SIMULATED DATA — not a live scan]" if simulated else "")
                + f"\nDescription: {description}\n"
                f"Remediation: {solution or 'No remediation recorded.'}"
            )

            metadata = {
                "cve_id": cve_id,
                "title": f"Scan #{scan_id} — {label} on {location}",
                "source_type": "scan_result",
                "scan_id": scan_id,
                "target": target,
                "severity": severity,
                "cvss_score": cvss,
                "exploit_available": getattr(vuln, "exploit_available", False),
                "source_scanner": scanner,
                "affected_host": host,
                "affected_port": port,
                "affected_service": service,
                # Carried into the prompt so the model can caveat simulated
                # findings instead of presenting them as observed fact.
                "simulated": simulated,
            }

            documents.append({
                "content": text,
                "id": f"scan{scan_id}-vuln{getattr(vuln, 'id', len(documents))}",
                "metadata": metadata,
            })

        pipeline = self._ensure_pipeline()
        added = pipeline.add_documents(documents)
        logger.info(
            "Indexed %d chunks from %d findings of scan %d into vector store",
            added, len(documents), scan_id,
        )
        return added

    @staticmethod
    def _short_title(description: str, limit: int = 70) -> str:
        """First clause of a description, for use as a document title."""
        text = (description or "").strip().split("\n")[0]
        if len(text) <= limit:
            return text
        return text[:limit].rsplit(" ", 1)[0] + "..."

    def query(
        self, question: str, n_results: int = 5, session_id: str | None = None
    ) -> dict:
        """Query the RAG system.

        Args:
            question: User question
            n_results: Number of results to retrieve
            session_id: Optional chat session ID for conversation history

        Returns:
            Dict with 'answer' and 'sources' keys
        """
        try:
            pipeline = self._ensure_pipeline()
            rag_query = RAGQuery(
                question=question,
                session_id=session_id,
                top_k=n_results,
                include_sources=True,
                conversation_history=bool(session_id),
            )
            response: RAGResponse = pipeline.query(rag_query)

            # Convert sources to the format the backend expects
            sources = []
            for s in response.sources:
                sources.append(
                    {
                        "cve_id": s.get("metadata", {}).get("cve_id"),
                        "content": s.get("content", ""),
                        "score": round(s.get("score", 0), 4),
                    }
                )

            return {
                "answer": response.answer,
                "sources": sources,
                "session_id": response.session_id,
            }

        except Exception:
            logger.exception("RAG query failed")
            return {
                "answer": "Unable to query the vulnerability database. Please try again later.",
                "sources": [],
            }

    def query_with_pipeline(
        self,
        question: str,
        pipeline_type: str = "default",
        session_id: str | None = None,
        n_results: int = 5,
    ) -> dict:
        """Query with a specialized pipeline (remediation, exploit, attack_path)."""
        try:
            pipeline = get_rag_pipeline(pipeline_type)
            pipeline.initialize()

            rag_query = RAGQuery(
                question=question,
                session_id=session_id,
                top_k=n_results,
                include_sources=True,
                conversation_history=bool(session_id),
            )
            response: RAGResponse = pipeline.query(rag_query)

            sources = []
            for s in response.sources:
                sources.append(
                    {
                        "cve_id": s.get("metadata", {}).get("cve_id"),
                        "content": s.get("content", ""),
                        "score": round(s.get("score", 0), 4),
                    }
                )

            return {
                "answer": response.answer,
                "sources": sources,
                "session_id": response.session_id,
                "pipeline": pipeline_type,
            }

        except Exception:
            logger.exception(f"RAG query with pipeline '{pipeline_type}' failed")
            return {
                "answer": "Unable to process your query. Please try again later.",
                "sources": [],
            }

    def get_stats(self) -> dict:
        """Get RAG system statistics."""
        try:
            pipeline = self._ensure_pipeline()
            return pipeline.get_stats()
        except Exception:
            return {"error": "Unable to retrieve stats"}

    def get_conversation_history(self, session_id: str, limit: int = 10) -> list:
        """Get chat history for a session."""
        return self.conversation_memory.get_conversation_history(
            session_id, limit=limit
        )

    def clear_session(self, session_id: str) -> bool:
        """Clear a chat session."""
        return self.conversation_memory.clear_session(session_id)

    def delete_session(self, session_id: str) -> bool:
        """Delete a chat session."""
        return self.conversation_memory.delete_session(session_id)


# Singleton instance
rag_engine = RAGEngine()
