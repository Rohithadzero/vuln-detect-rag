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

    def reset(self) -> None:
        """Drop every cached component so the next call rebuilds them.

        Called when the LLM topology changes — a provider toggled, a model
        pinned, retrieval switched off. Without this the engine keeps serving
        the client it built at first use and the Settings toggles appear to do
        nothing until the process restarts.

        The embedding service and vector store are deliberately preserved:
        they are unaffected by LLM changes and reloading the embedding model
        costs several seconds.
        """
        from rag_assistant.chains.rag_chain import reset_pipelines

        reset_pipelines()
        self._pipeline = None
        self._llm_client = None
        logger.info("RAG engine caches cleared")

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

    def index_cves(self, cve_entries: list[dict], enrich: bool = True,
                   nvd_limit: int | None = None) -> int:
        """Index CVE entries into the vector store.

        Each document is written to stand alone in a prompt: the retrieved
        chunk is all the model sees, so severity, exploitation status, weakness
        class and remediation are stated in the text itself rather than living
        only in metadata the model never reads.

        Documents are tagged ``source_type='cve_database'`` so retrieval can be
        scoped to the static knowledge base.

        Args:
            cve_entries: CVE records from the local corpus.
            enrich: Add free threat intelligence (CISA KEV, EPSS, NVD).
            nvd_limit: Cap on uncached NVD lookups, which are rate-limited.
        """
        if not cve_entries:
            return 0

        enrichment: dict[str, dict] = {}
        if enrich:
            try:
                from services.enrichment import cve_enricher

                cve_ids = [e.get("cve_id", "") for e in cve_entries]
                enrichment = cve_enricher.enrich(cve_ids, nvd_limit=nvd_limit)
                enriched_count = sum(1 for v in enrichment.values() if v)
                kev_count = sum(1 for v in enrichment.values() if v.get("kev"))
                logger.info(
                    "Enriched %d/%d CVEs (%d known-exploited)",
                    enriched_count, len(cve_entries), kev_count,
                )
            except Exception:
                # Enrichment is an enhancement, never a prerequisite: a network
                # failure must not stop the corpus being indexed.
                logger.exception("Enrichment failed; indexing without it")

        documents = []
        for entry in cve_entries:
            cve_id = (entry.get("cve_id") or "").upper()
            record = enrichment.get(cve_id, {})
            documents.append(
                self._build_cve_document(entry, cve_id, record)
            )

        pipeline = self._ensure_pipeline()
        added = pipeline.add_documents(documents)
        logger.info(f"Indexed {added} CVE chunks into vector store")
        return added

    def _build_cve_document(self, entry: dict, cve_id: str, record: dict) -> dict:
        """Compose one richly-described CVE document plus its metadata."""
        from services.enrichment import CVEEnricher

        description = entry.get("description", "")
        solution = entry.get("solution", "")
        severity = entry.get("severity", "LOW")
        cvss = entry.get("cvss_score", 0.0)
        references = entry.get("references", []) or []
        exploit_available = entry.get("exploit_available", False)

        # Written as headed prose. Section labels give the model reliable
        # anchors to quote, and spelling out the severity band means it never
        # has to infer what "9.8" implies.
        sections = [
            f"# {cve_id} — {self._short_title(description)}",
            "",
            f"Identifier: {cve_id}",
            f"Severity: {severity} (CVSS base score {cvss} out of 10) — "
            f"{self._severity_meaning(severity, cvss)}",
        ]

        enrichment_text = CVEEnricher.describe(cve_id, record)
        if enrichment_text:
            sections.append(enrichment_text)
        elif exploit_available:
            sections.append(
                "Exploitation status: public exploit code is reported to exist."
            )

        sections.extend([
            "",
            "## Description",
            description or "No description recorded.",
            "",
            "## Remediation",
            solution or "No remediation recorded for this entry.",
        ])

        combined_refs = list(dict.fromkeys(
            [*references, *(record.get("references") or [])]
        ))[:8]
        if combined_refs:
            sections.extend(["", "## References", *(f"- {r}" for r in combined_refs)])

        metadata = {
            "cve_id": cve_id,
            "title": f"{cve_id} — {self._short_title(description)}",
            "source_type": "cve_database",
            "source": entry.get("source", "NVD"),
            "severity": severity,
            "cvss_score": cvss,
            "exploit_available": exploit_available,
            # Coarse year bucket, so queries can be filtered by recency.
            "year": self._cve_year(cve_id),
            **CVEEnricher.metadata(record),
        }

        return {
            "content": "\n".join(sections),
            "id": cve_id or None,
            "metadata": metadata,
        }

    #: Prompt for turning a raw scan report into an explanation a human can act
    #: on. Kept separate from the chat persona because this is a briefing, not
    #: a conversation: the reader has not asked a question, so the answer has to
    #: lead with what matters rather than respond to one.
    SCAN_EXPLAIN_PROMPT = """You are a senior security analyst briefing the owner of a system on the results of a vulnerability scan.

GROUNDING RULES (these override everything else):
1. Describe only findings present in the scan report below. Invent nothing.
2. Never invent CVE IDs, CVSS scores, versions, or hosts.
3. If a finding is marked SIMULATED, say so explicitly and do not present it as
   an observed fact about the target.
4. If the report contains no findings, say that plainly.

Write the briefing in this order:
1. **Bottom line** — one or two sentences: how exposed is this target, and is
   anything being actively exploited right now?
2. **Fix first** — the findings that matter most, worst first. For each: what
   it is in plain language, what an attacker could actually do with it, and the
   specific remediation. Prioritise anything on the CISA KEV catalogue or with a
   high EPSS score over anything that merely has a high CVSS score, and say why.
3. **Everything else** — briefly group the remaining findings.
4. **Caveats** — scanner coverage limits, simulated findings, and what this
   scan did not check.

Write for a competent engineer who is not a security specialist. Explain jargon
in passing. Be concrete and brief; no filler."""

    def explain_scan(self, scan_id: int, target: str, vulnerabilities: list,
                     question: str | None = None) -> dict:
        """Turn a completed scan into a plain-language briefing.

        This is the final step of the product flow: a target is scanned, the
        selected tools return findings, those findings are chunked and indexed,
        and the model explains what they mean. Without it the user is left
        reading a raw CVE table, which is exactly the expertise barrier the
        system exists to remove.

        Args:
            scan_id: Scan to explain.
            target: Scan target.
            vulnerabilities: VulnerabilityDB rows for the scan.
            question: Optional specific question about this scan; when omitted
                a full briefing is produced.

        Returns:
            Dict with the explanation, its sources, and telemetry.
        """
        if not vulnerabilities:
            return {
                "explanation": (
                    f"The scan of {target} completed without recording any "
                    f"findings. That means the selected tools reported nothing, "
                    f"not that the target is necessarily secure — check the "
                    f"scanner availability on the Settings page."
                ),
                "sources": [],
                "scan_id": scan_id,
                "finding_count": 0,
            }

        pipeline = self._ensure_pipeline()

        # Retrieval is scoped to this scan so the briefing describes the target
        # in front of the user, not similar CVEs from the background corpus.
        rag_query = RAGQuery(
            question=question or (
                f"Explain the vulnerability scan results for {target} and tell "
                f"me what to fix first."
            ),
            top_k=min(len(vulnerabilities), 12),
            include_sources=True,
            conversation_history=False,
            filters={"scan_id": scan_id},
        )

        try:
            results = pipeline.retrieve(rag_query)

            # The vector store may not have caught up (indexing is best-effort
            # and asynchronous), so fall back to rendering the rows directly.
            if not results:
                logger.info(
                    "Scan %d not found in the vector store; explaining from "
                    "the database rows instead", scan_id,
                )
                context = self._render_findings(scan_id, target, vulnerabilities)
                sources = []
            else:
                context = pipeline._build_context(results)
                sources = [
                    {
                        "cve_id": (r.metadata or {}).get("cve_id"),
                        "content": r.document.content[:300],
                        "score": round(r.score, 4),
                    }
                    for r in results
                ]

            prompt = (
                f"{context}\n\n"
                f"=== SCAN UNDER REVIEW ===\n"
                f"Target: {target}\n"
                f"Scan ID: {scan_id}\n"
                f"Total findings: {len(vulnerabilities)}\n\n"
                f"Write the briefing described in your instructions."
            )
            if question:
                prompt += f"\n\nThe user specifically asks: {question}"

            result = pipeline.llm_client.generate_detailed(
                prompt, system=self.SCAN_EXPLAIN_PROMPT, max_tokens=3000
            )
            if result.error:
                raise RuntimeError(result.error)

            return {
                "explanation": result.text,
                "sources": sources,
                "scan_id": scan_id,
                "finding_count": len(vulnerabilities),
                "llm_provider": result.provider,
                "llm_model": result.model,
                "generation_ms": result.latency_ms,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
            }

        except Exception as e:
            logger.exception("Failed to explain scan %d", scan_id)
            return {
                "explanation": (
                    "The scan results could not be explained because the "
                    f"language model is unavailable: {e}"
                ),
                "sources": [],
                "scan_id": scan_id,
                "finding_count": len(vulnerabilities),
                "error": str(e),
            }

    def _render_findings(self, scan_id: int, target: str,
                         vulnerabilities: list) -> str:
        """Render scan rows as prompt context, worst first.

        Used when the vector store has not yet indexed the scan, so an
        explanation is still possible immediately after a scan completes.
        """
        ordered = sorted(
            vulnerabilities,
            key=lambda v: getattr(v, "cvss_score", 0) or 0,
            reverse=True,
        )

        lines = [f"=== SCAN REPORT: {target} (scan #{scan_id}) ==="]
        for index, vuln in enumerate(ordered[:25], 1):
            raw_output = getattr(vuln, "raw_output", None) or {}
            simulated = raw_output.get("type") == "mock"
            host = getattr(vuln, "affected_host", "") or target
            port = getattr(vuln, "affected_port", None)
            location = f"{host}:{port}" if port else host

            lines.append(
                f"\n[Doc {index}] "
                f"{getattr(vuln, 'cve_id', None) or 'Unnamed finding'} "
                f"({getattr(vuln, 'severity', 'LOW')}, "
                f"CVSS {getattr(vuln, 'cvss_score', 0)})"
                + (" [SIMULATED DATA]" if simulated else "")
            )
            lines.append(f"Location: {location}")
            lines.append(f"Detected by: {getattr(vuln, 'source_scanner', 'unknown')}")
            lines.append(f"Description: {getattr(vuln, 'description', '')}")
            solution = getattr(vuln, "solution", "")
            lines.append(f"Remediation: {solution or 'None recorded.'}")

        if len(ordered) > 25:
            lines.append(f"\n(+{len(ordered) - 25} further lower-severity findings)")

        return "\n".join(lines)

    @staticmethod
    def _severity_meaning(severity: str, cvss: float) -> str:
        """Plain-language reading of a severity band.

        Spelled out so the model does not have to infer operational urgency
        from a bare number, which is a common source of vague answers.
        """
        try:
            score = float(cvss)
        except (TypeError, ValueError):
            score = 0.0

        if score >= 9.0:
            return ("critical risk, typically remotely exploitable with severe "
                    "impact; patch immediately")
        if score >= 7.0:
            return "high risk; prioritise patching in the current cycle"
        if score >= 4.0:
            return "medium risk; schedule remediation"
        if score > 0:
            return "low risk; remediate opportunistically"
        return "severity not scored"

    @staticmethod
    def _cve_year(cve_id: str) -> int:
        """Year component of a CVE identifier, or 0 when unparseable."""
        try:
            return int(cve_id.split("-")[1])
        except (IndexError, ValueError):
            return 0

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

        # Same threat intelligence as the CVE corpus, so the assistant can say
        # whether a finding on this host is actually being exploited in the wild.
        from services.enrichment import CVEEnricher, cve_enricher

        enrichment: dict[str, dict] = {}
        try:
            scan_cves = [
                getattr(v, "cve_id", None) for v in vulnerabilities
                if getattr(v, "cve_id", None)
            ]
            if scan_cves:
                enrichment = cve_enricher.enrich(scan_cves, include_nvd=False)
        except Exception:
            logger.exception("Scan enrichment failed; indexing without it")

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
            record = enrichment.get((cve_id or "").upper(), {})

            sections = [
                f"# Scan #{scan_id} finding on {target}: {label}",
                "",
                f"Target: {target}",
                f"Location: {location}" + (f" running {service}" if service else ""),
                f"Severity: {severity} (CVSS {cvss}) — "
                f"{self._severity_meaning(severity, cvss)}",
                f"Detected by: {scanner or 'unknown scanner'}",
            ]
            if simulated:
                sections.append(
                    "DATA QUALITY WARNING: this finding is SIMULATED sample "
                    "data produced because the scanner was unavailable. It "
                    "does not describe the real state of the target and must "
                    "not be treated as an observed result."
                )

            enrichment_text = CVEEnricher.describe(cve_id or "", record)
            if enrichment_text:
                sections.append(enrichment_text)

            sections.extend([
                "",
                "## Description",
                description or "No description recorded.",
                "",
                "## Remediation",
                solution or "No remediation recorded.",
            ])
            text = "\n".join(sections)

            metadata = {
                **CVEEnricher.metadata(record),
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
