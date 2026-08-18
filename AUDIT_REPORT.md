# AUDIT_REPORT.md — Emet / VulnDetectRAG (`vuln-detect-rag`)

**Audit date:** 2026-08-18
**Audited tree:** `vuln-detect-rag/` (git repo root). All line references are relative to this directory unless noted.
**Method:** Direct code reading, plus inspection of the on-disk SQLite and ChromaDB artifacts. README/docstring claims were treated as unverified until confirmed in code.

### Scope note — three copies of the codebase exist

The repo root contains the canonical tree *and* two nested, untracked full copies:

| Tree | Git status | Newest source mtime | Notes |
|---|---|---|---|
| `backend/`, `frontend/`, `rag_assistant/`, `scripts/` (root) | Tracked, 42 files modified/untracked vs. HEAD | 2026-05-05 | **Canonical — audited here** |
| `EMET/` | Untracked (`?? EMET/`) | 2026-03-28 | Netlify-targeted variant; adds a browser-side Groq client and a pure-JS mock scanner (see §6) |
| `v1.5/` | Untracked (`?? v1.5/`) | 2026-03-28 | Older snapshot |

`backend/venv/` is also present and committed-adjacent; its `pyvenv.cfg` points at `C:\PU Hackethon\vuln-detect-rag\backend\venv` with base interpreter `C:\Python314\python.exe`, which does not exist on this machine. **The bundled venv is not runnable as-is**, so nothing in this audit was executed against the project's own dependency set; the ChromaDB behavioral check in §3 was run against a separately installed `chromadb` (see that section for the caveat).

---

## 1. Scanner integrations — what's real vs. simulated

Six scanners are registered, not four. `SCANNER_MAP` at `backend/services/orchestrator.py:20-27` lists `nmap`, `nuclei`, `openvas`, `nessus`, `burp`, `zap`.

### Per-scanner verdict

| Scanner | Live path exists? | Reaches real tool in practice? | Mock fallback |
|---|---|---|---|
| **Nmap** | Yes — real `subprocess.run` | Yes, if the binary is found | Yes, on every failure path |
| **Nuclei** | Yes — real `subprocess.run` | Yes, if the binary is found | Yes, on most failure paths |
| **OpenVAS** | **No** | Never | Always |
| **Nessus** | **No** | Never | Always |
| **Burp** | Partially — real HTTP client, but CLI path is a hardcoded raise | Only if Burp Pro REST API is already running | Yes |
| **ZAP** | Yes — real HTTP + CLI paths | Only if ZAP daemon/binary present | Yes |

**Nmap** (`backend/scanners/nmap_scanner.py`) is a genuine adapter. It resolves a binary from `settings.NMAP_PATH`, `PATH`, then a per-OS list of common install paths (`:22-61`), validates the target against `^[a-zA-Z0-9._-]+$` before shelling out (`:66-71`), and runs `nmap -sV -sC --script vulners -oX - -T4 --top-ports 1000 <target>` with a 600 s timeout (`:84-104`). Raw output is **XML on stdout**, parsed by `_parse_xml` (`:127-181`) with `defusedxml` when available and stdlib `xml.etree` otherwise (`:10-15`). If no CVEs are found it degrades to open-port enumeration (`_parse_open_ports`, `:227-282`). Mock is used when the binary is missing, the target fails validation, the process times out, or any exception fires (`:76-125`).

**Nuclei** (`backend/scanners/nuclei_scanner.py`) is likewise genuine: binary resolution at `:30-58`, and `nuclei -u <url> -jsonl -silent -severity critical,high,medium -timeout 10 -retries 1 -c 50` at `:76-98`. Raw output is **JSONL, one finding per line**, parsed at `:117-176` handling both nuclei v2 and v3 key spellings (`template-id`/`templateID`, `matched-at`/`matched`). Note an asymmetry with nmap: a *successful* nuclei run that returns zero findings returns `[]` rather than mock data (`:106-109`), whereas failures return mock (`:110-115`).

**OpenVAS** (`backend/scanners/openvas_scanner.py`) is **entirely mocked**. The whole file is 70 lines: `is_available()` hardcodes `return False  # Requires full GVM setup` (`:7-8`), and `scan()` unconditionally calls `_mock_scan()` (`:10-11`). There is no GVM/GMP client, no socket code, no XML parsing. The mock returns a fixed list of 4 `ScanVulnerability` objects (CVE-2023-36884, CVE-2022-47966, CVE-2023-20198, CVE-2023-22515) that is **identical for every target** — the only target-dependent field is `affected_host`.

**Nessus** (`backend/scanners/nessus_scanner.py`) is **entirely mocked**, structurally identical to OpenVAS. `is_available()` returns `False` (`:7-8`); `scan()` returns 5 hardcoded findings (ProxyLogon, Citrix Bleed, FortiOS, PAN-OS, TP-Link) with no target variation beyond `affected_host` (`:13-84`). No `.nessus` file parsing, no Tenable API client.

**Burp** (`backend/scanners/burp_scanner.py`, 313 lines) has a real REST client — `httpx.post` to `http://127.0.0.1:1337/v0.1/scan`, then polls for up to 10 minutes (`:120-156`) — and a real parser for Burp's `issue_events.issue_added` shape (`:158-194`). The **CLI path is a deliberate stub**: `_scan_via_cli` builds a command list and then unconditionally executes `raise Exception("Burp CLI automation not fully supported")` at `:210`, so the `cmd` variable is dead code. Requires Burp *Professional* with the REST API already listening.

**ZAP** (`backend/scanners/zap_scanner.py`, 397 lines) has the most complete live implementation of the three optional scanners: a three-stage API flow (spider → active scan → fetch alerts) against `http://127.0.0.1:8080/JSON/...` (`:119-175`), and a CLI path invoking `zap -quickurl <url> -quickout /tmp/zap_report.json -quickprogress -cmd` (`:240-274`). Two caveats: the CLI writes to the POSIX path `/tmp/zap_report.json`, which will not resolve on the Windows deployment target; and `_parse_cli_output` (`:276-280`) is a stub that returns `[]` with the comment "ZAP CLI output parsing is limited, return empty to fall back to mock", so the CLI path only yields data when the JSON report file is readable.

### Mock data structure and fidelity

All mocks are defined **inline in each scanner's `_mock_scan` method** — there is no shared fixture file. They do not resemble real tool output at all: they are pre-constructed `ScanVulnerability` dataclass instances, i.e. they enter the pipeline *after* the parsing stage. Real nmap XML and nuclei JSONL never exist on the mock path, so the parsers are never exercised by mock runs.

Nmap and nuclei mocks are pseudo-deterministic per target: `hashlib.md5(target)` (nmap, `:284-289`) or `md5(target + "nuclei")` (nuclei, `:183-186`) seeds modulo checks that gate which findings appear, producing 1–4 findings that vary by target while remaining stable across runs. ZAP and Burp use the same `md5(target + name)` trick. OpenVAS and Nessus do not — their output is constant.

Every mock finding carries `raw_output={"type": "mock", ...}`, so mock-vs-live provenance **is** distinguishable downstream. Nothing in the API, DB schema, or frontend currently reads that flag to surface the distinction to the user.

### Scanners not mentioned in the README

None. The README (line ~9 and the Tech Stack table) already lists all six and correctly labels OpenVAS and Nessus as "(Mock)" and Burp/ZAP as "(API/CLI/Mock)". On this point the README is accurate.

---

## 2. Data schema — what unification actually exists today

### A unified schema exists

`ScanVulnerability` — `backend/scanners/base.py:6-21` — a `@dataclass` with 12 fields:

`cve_id`, `cvss_score`, `severity`, `description`, `affected_host`, `affected_port`, `affected_service`, `solution`, `references`, `exploit_available`, `source_scanner`, `raw_output`.

Every scanner's `scan()` is contractually typed `-> list[ScanVulnerability]` by the `ScannerAdapter` ABC (`base.py:24-32`), and all six adapters — live paths and mock paths alike — construct `ScanVulnerability` objects directly. **No scanner's output stays in its native shape past its own adapter.** Normalization happens at parse time, inside each adapter, not in a downstream mapper.

The schema is mirrored, field for field, into the persistence layer as `VulnerabilityDB` (`backend/models/database.py:56-75`) and into the API layer as `VulnerabilityResponse` (`backend/models/schemas.py`). The chain `ScanVulnerability → VulnerabilityDB → VulnerabilityResponse → frontend` is used by the whole pipeline; nothing bypasses it.

Native tool output is preserved lossily in the `raw_output` JSON blob — nmap stores `{"script": ..., "output": <first 500 chars>}` (`nmap_scanner.py:173-176`), nuclei stores `{"template": ..., "type": ...}` (`nuclei_scanner.py:167-170`). Full raw output is discarded.

### Conflict resolution — a naive form exists; a real one does not

`AggregatorService.aggregate` (`backend/services/aggregator.py:8-67`) does perform cross-scanner merging:

- **Dedup key** (`:14-17`): `cve_id` when present, otherwise the composite `f"{affected_host}:{affected_port}:{description[:50]}"`.
- **Disagreement resolution** (`:18-32`): when two scanners report the same key, **the higher `cvss_score` wins outright**, and the loser's `references` are merged into the winner's list. Nothing else is merged.
- **Severity re-normalization** (`:34-37`): severity is recomputed from CVSS via fixed thresholds (≥9.0 CRITICAL, ≥7.0 HIGH, ≥4.0 MEDIUM, else LOW), so a scanner's own severity label is overridden whenever it reported a CVE with a nonzero score.

What this means for the research framing: there **is** a merge step, and it does resolve numeric CVSS disagreement — but it is max-wins, not consensus, confidence-weighted, or provenance-preserving. Concretely, the following are **absent**:

- No record that two scanners agreed (no corroboration count, no confidence score).
- **`source_scanner` is silently overwritten by the winner** — after aggregation a finding attributes to exactly one scanner even if four found it. Multi-scanner agreement is unrecoverable from the persisted data.
- No handling of *semantic* disagreement — differing `description`, `solution`, `affected_service`, or `exploit_available` for the same CVE are not reconciled; the loser's values are dropped.
- `exploit_available` is not OR-ed across sources.
- No conflict is ever logged, surfaced in the API, or shown in the UI.

There is no other reconciliation logic anywhere in the codebase; `aggregator.py` is the only place cross-scanner merging happens (called once, from `orchestrator.py:81`).

### CVE/CVSS data sourcing

**Bundled static dataset, no live API call anywhere.** There is no NVD client, no `nvd.nist.gov` fetch, no CVE feed refresh job.

- `backend/data/sample_nvd.json` — a 50-entry JSON array (verified: 50 records, 50 unique CVE IDs), fields `cve_id`, `cvss_score`, `severity`, `description`, `solution`, `references`, `exploit_available`, `source`. CVE years span **2020–2024 only**.
- `backend/data/exploitdb_sample.json` — 5 entries (`exploit_id`, `cve_id`, `title`, `type`, `platform`, `description`, `source`). **Loaded by nothing** — no code path reads this file.
- Loaded by `scripts/seed_cve_data.py:13-69`, which dedups by `cve_id`, inserts into the `cve_entries` SQLite table, and calls `rag_engine.index_cves()`.

Currency: the newest CVE in the bundle is from 2024; there is no mechanism to update it. The README claims "40+ real-world CVEs" — the actual count is 50, so that claim is conservative and accurate.

CVSS scores from *live* scans are derived, not authoritative: nmap tries three successive heuristics to scrape a CVSS out of vulners script text, the last of which is "grab the first `\d+\.\d+` within ±2 lines of the CVE ID" (`nmap_scanner.py:212-222`) — a regex that will happily capture a version number. Nuclei falls back to a fixed severity→CVSS table (CRITICAL→9.5, HIGH→7.5, MEDIUM→5.0, LOW→2.5) when `classification.cvss-score` is absent (`nuclei_scanner.py:178-180`); Burp and ZAP use the same table.

Live DB state at audit time: `cve_entries` = 50 rows, `vulnerabilities` = 157 rows across 9 `scans`, `chat_messages` = 25.

---

## 3. RAG pipeline — actual architecture

### Retrieval mechanism

- **Vector store:** ChromaDB by default, selected by `VECTOR_STORE_TYPE` (`rag_assistant/vectorstore/vector_store.py:437-444`). A FAISS implementation exists (`:276-420`) but is not the default and has a hardcoded `dimension = 1536` (`:300`) that does not match the 384-dim MiniLM embeddings the project actually produces — the FAISS path would fail if selected.
- **Embeddings:** `EmbeddingService` (`rag_assistant/embeddings/embedding_service.py`), default provider `local` → `langchain_huggingface.HuggingFaceEmbeddings` with `all-MiniLM-L6-v2` (`:123-136`). OpenAI, HuggingFace-API, and Ollama embedding backends also exist (`:46-121`).
- **What's indexed:** one document per CVE entry. `RAGEngine.index_cves` (`backend/services/rag_engine.py:100-121`) builds the text as `f"{cve_id}: {description} Solution: {solution}"` and metadata `{cve_id, severity, cvss_score, exploit_available}`.
- **Chunking:** **none in practice.** A `chunk_text` static method exists (`embedding_service.py:160-197`, 500 chars with 50-char overlap and sentence-boundary snapping) but **it is never called** — grep finds no invocation. Each CVE is embedded whole as a single document.

### Three defects in the retrieval path

These matter for any claim that the system performs grounded retrieval:

1. **Embeddings are computed and then discarded on write.** `ChromaVectorStore.add_documents` builds `embeddings = [doc.embedding for doc in documents if doc.embedding]` at `:189` and then **never passes it** to `self.collection.add(...)` at `:191-195`, which receives only `ids`, `documents`, `metadatas`. Chroma therefore embeds with its own default function on write, while `search()` supplies a `query_embedding` from `EmbeddingService` on read (`:208-212`). The two embedding spaces coincide only because Chroma's default happens to also be `all-MiniLM-L6-v2` — this is accidental, and switching `EMBEDDING_PROVIDER` to `openai` or `ollama` would silently produce meaningless similarity scores rather than an error.

2. **Collection-name mismatch.** `backend/config.py:39` sets `CHROMA_COLLECTION = "cve_knowledge"`, but `ChromaVectorStore.__init__` defaults to `collection_name = "vulnerabilities"` (`:118`) and **never reads `settings.CHROMA_COLLECTION`**. Inspecting the on-disk store confirms the consequence: `backend/data/chroma/chroma.sqlite3` contains exactly one collection, named **`cve_knowledge`**, holding 50 embeddings — written by an earlier code revision. The current code would `get_or_create_collection("vulnerabilities")`, i.e. create a fresh empty collection and **retrieve nothing from the 50 indexed CVEs** until a re-index is run under the current code path. (The same is true of the duplicate store at `scripts/data/chroma/`, also `cve_knowledge`/50.)

3. **Persistence is likely not enabled.** `:147-156` calls `chromadb.Client(Settings(persist_directory=..., anonymized_telemetry=False))` when the directory exists, and `chromadb.HttpClient(...)` when it does not. `Settings.is_persistent` defaults to `False` and is never set — I verified this default directly against an installed `chromadb` (`is_persistent default: False`). *Caveat:* that check ran against chromadb 1.5.7 on the system interpreter, not the project's pinned 0.6.3 (`backend/venv/Lib/site-packages/chromadb-0.6.3.dist-info`), because the bundled venv is unrunnable. The default has been `False` since the 0.4 line, so `Client(...)` is ephemeral and `persist_directory` alone does not enable durable storage — but this specific point is inferred for 0.6.3 rather than executed against it. The correct call is `chromadb.PersistentClient(path=...)`.

The net effect of (2) and (3): **the RAG assistant is very likely retrieving from an empty collection at runtime.** This should be verified interactively before any claim about retrieval quality is made in the paper.

### End-to-end trace of one query

Path: browser → `POST /api/rag/chat` → LLM.

1. `frontend/src/pages/RAGAssistant.jsx:54` — `chatRAG(message, sessionId)`; `sessionId` is a client-generated `session_${Date.now()}` (`:9`).
2. `frontend/src/api/client.js:38` — `POST /api/rag/chat {message, session_id}`.
3. `backend/api/routes_rag.py:26-60` — `chat()`. Persists the user turn to `chat_messages` (`:30`), then builds `RAGQuery(question=request.message, session_id=session_id)` (`:33`) and calls `rag_pipeline.query()` (`:34`). The pipeline is a **module-level singleton** created at import time (`:21`).
4. `rag_assistant/chains/rag_chain.py:133-206` — `RAGPipeline.query()`:
   - `:148` embed the question via `EmbeddingService`;
   - `:150-154` `vector_store.search(query_embedding, top_k=5, filter_metadata=None)` — `top_k` defaults to 5 (`RAGQuery.top_k`, `:23`); note `routes_rag.py:33` does not override it;
   - `:156` `_build_context(search_results)`;
   - `:158-162` because `RAGQuery.conversation_history` defaults to `True` (`:25`), it pulls the last 5 turns from `ConversationMemory` and takes the with-history prompt branch;
   - `:164` `llm_client.generate(prompt)` — a single, non-streaming completion;
   - `:166-176` writes both turns into `ConversationMemory`;
   - `:178-187` truncates each source's content to 200 chars for the response payload.
5. `routes_rag.py:43-60` maps sources to `ChatSource(cve_id, content, score)`, persists the assistant turn, returns `ChatResponse`.

**Exactly what lands in the prompt** (`_build_prompt_with_history`, `:272-299`), concatenated as one string:

- The `SYSTEM_PROMPT` — a fixed ~19-line cybersecurity-expert persona block (`:40-59`).
- The retrieved context (`_build_context`, `:223-252`): a `"Context from vulnerability database:"` header, then per document a `--- Document {i} (Relevance: {score:.2f}) ---` header, `Source:` (from `metadata.source_type`, **never set by the indexer** — always renders `unknown`), `Title:` (from `metadata.title`, **also never set** — always `Untitled`), the full document text, then `CVE ID:` and `CVSS Score:` lines when those metadata keys exist. With zero results the entire context degrades to the literal string `"No relevant documents found."` (`:232-233`).
- Conversation history: the last 6 messages, each **truncated to 200 characters with an appended `"..."`** (`:286-289`).
- The user question, then a fixed closing instruction.

There is no re-ranking, no relevance thresholding, no citation enforcement, and no guard that drops the context block when retrieval returns nothing — on an empty store the model is prompted to answer from parametric memory alone while the UI still labels the reply as coming from the vulnerability assistant.

### Grounding

Grounded in **the separate, static CVE knowledge base, not in live scan results.** The only writer to the vector store is `RAGEngine.index_cves` (`rag_engine.py:100-121`), called only from `scripts/seed_cve_data.py:65`, which reads only `sample_nvd.json`. **`ScanVulnerability` / `VulnerabilityDB` rows are never indexed.** The RAG assistant therefore cannot answer questions about a scan the user just ran; scan results and the RAG corpus are fully disconnected data paths that meet nowhere in the codebase.

### Models and cloud fallbacks

`LLMFactory` (`rag_assistant/llm_config.py:270-373`) supports **four** providers: `ollama`, `openai`, `groq`, `huggingface`. Default is `ollama` via `LLM_PROVIDER` (`:330`).

- **Ollama:** default model `qwen2.5-coder:7b`, overridable by `OLLAMA_MODEL`, base URL `http://localhost:11434`. `check_ollama_available()` (`:274-311`) shells out to `ollama list` and — notably — **auto-selects `models[0]` when the configured model is absent** (`:303-306`), so the model actually answering may differ from the configured one. `OllamaClient.generate` calls `ollama.chat` (`:128-138`); note it ignores `temperature` and `max_tokens` entirely, unlike the other three clients.
- **Cloud fallbacks: yes, three.** `OpenAIClient` (`:60-104`, default `gpt-4o`), `GroqClient` (`:153-201`, default `llama-3.1-70b-versatile`, OpenAI-compatible endpoint), `HuggingFaceClient` (`:204-267`, Inference API). These are *alternatives selected by env var*, not automatic failover — if Ollama is down, the request raises rather than falling back. The privacy-first claim holds for the default configuration only.
- Additionally, `EMET/frontend/src/api/groqClient.js` calls `api.groq.com` **directly from the browser** with `VITE_GROQ_API_KEY` — outside the Python pipeline entirely. Not part of the audited root tree, but relevant to any "no data leaves your machine" claim about the deployed EMET build.

### Conversation memory

**Yes — multi-turn, at two independent layers.**

1. `ConversationMemory` (`rag_assistant/memory/conversation_memory.py:104+`) — in-process dict of `ConversationContext`, capped at 100 sessions × 100 messages, LRU-evicted via a `deque`. This is what feeds the prompt. It is **not persisted**: a backend restart wipes it, while the SQLite history survives, so replayed sessions silently lose their prompt-level context.
2. `ChatMessageDB` (`backend/models/database.py:94-102`) — durable SQLite history used by `GET /api/rag/history/{session_id}` and the session sidebar.

A `RedisConversationMemory` subclass exists (`:240-327`) with TTL-based persistence, but `get_conversation_memory()` defaults to `backend='memory'` (`:330-341`) and no caller passes `'redis'`. `redis` is not in `requirements.txt`.

---

## 4. Evaluation — what's actually measured today

### The eval script

`scripts/run_eval.py` (96 lines) is the only evaluation entry point. Read in full.

**Metrics computed (all of them):**

1. **CVE detection** — precision, recall, F1, plus a separately reported `detection_rate`, and raw TP/FP/FN counts (`backend/services/evaluators.py:10-42`).
2. **BLEU** — hand-rolled BLEU-1 through BLEU-4 with a brevity penalty and geometric mean (`:44-94`). Reports the composite plus each n-gram precision and the BP. Note: no smoothing — any zero n-gram precision collapses the whole score to 0.0 (`:75-82`).
3. **ROUGE** — ROUGE-1, ROUGE-2, and ROUGE-L (LCS-based, O(mn) DP), each with precision/recall/F1, plus their unweighted mean as the headline score (`:96-125`, `:133-183`).

That is the complete list. No MRR, NDCG, hit-rate, recall@k, faithfulness, hallucination rate, answer relevance, or any retrieval-specific metric. All metrics are implemented from scratch — `nltk` is declared in `requirements.txt` but **never imported** by project code.

### What it compares against — nothing live

**This is the most significant gap for the paper.** `run_eval.py` does not import, instantiate, or call the RAG pipeline, the vector store, the LLM, or any scanner. Every input is a Python literal in the script body:

- The "predicted" CVE list (`:19-23`) and "ground truth" list (`:24-28`) are two hardcoded 9-element arrays. They overlap in 6 elements by construction, which is what produces the F1 of 0.6667.
- The BLEU/ROUGE "prediction" (`:49-53`) and "reference" (`:43-48`) are two hardcoded paragraphs about Log4Shell. The "prediction" was not generated by the system.

**There is no ground-truth dataset file anywhere in the repo** — no expert annotations, no labeled Q&A pairs, no reference answers on disk. Nothing was constructed; the numbers are fixed constants dressed as measurements. Re-running the script on a different machine, a different model, or a broken retriever produces byte-identical output.

This is load-bearing for the write-up: `research_paper.md` (Abstract) reports "a CVE Detection F1 score of 0.6667, ROUGE score of 0.4809". Those are exactly the values `run_eval.py` emits from its literals. **They measure nothing about the system** and cannot support a claim of "comprehensive evaluation."

### Ablations, baselines, comparison conditions

**None — not even partial.** No no-RAG condition, no retrieval-off variant, no alternate-k sweep, no model comparison, no scanner-subset comparison. The four `get_rag_pipeline()` variants (`default`, `remediation`, `exploit`, `attack_path` — `rag_chain.py:390-406`) differ only in system prompt and could serve as a prompt ablation, but nothing compares them: `routes_rag.py:21` hardcodes `"default"`, and `RAGEngine.query_with_pipeline` (`rag_engine.py:171-214`) — the only way to reach the other three — has **no route exposing it** and no caller anywhere.

### Latency, cost, resource logging

Minimal and non-persistent.

- **Latency:** one middleware measures per-request wall time and logs it at **DEBUG** level (`backend/main.py:112-124`). Since `DEBUG` defaults to `False` (`config.py:32`), the logger is at INFO and **these timings are not emitted in the default configuration**. They go to a rolling text log, never to a database, and are never aggregated. There is no separate instrumentation of retrieval time vs. LLM generation time vs. scan duration.
- **Scan duration** is *derivable* — `ScanDB.started_at` / `completed_at` (`database.py:51-52`) — but nothing computes or displays it.
- **Cost:** no tracking of any kind. No token counting, no prompt/completion length logging, no per-query accounting.
- **Resource usage:** none. No memory, CPU, or GPU instrumentation.

---

## 5. Frontend/dashboard — what a user can actually do

React 18 + Vite + Tailwind, six routes (`frontend/src/App.jsx:37-45`), all lazy-loaded, wrapped in an `ErrorBoundary` and a `ThemeProvider` (`main.jsx:10-14`).

### Complete feature inventory

**Dashboard (`/`, `pages/Dashboard.jsx`, 264 lines)**
- Aggregate stat cards from `GET /api/stats` — total scans, total vulns, severity counts, average CVSS.
- Recharts `BarChart` and `PieChart` of severity distribution (the only file importing `recharts`).
- Scanner availability indicators from `GET /api/health`.
- A quick-scan input that starts a scan and navigates to the console.
- Recent-scans list (last 10), click-through to a scan.
- Auto-refresh on a 30-second `setInterval` (`:38`).

**Scan Console (`/scans`, `pages/ScanConsole.jsx`, 209 lines)**
- Target input plus a **six-scanner multi-select** (`components/ScanForm.jsx:4-11`), defaulting to `['nmap', 'nuclei']`. All six are user-selectable, including the two that are pure mocks — with no UI signal that OpenVAS/Nessus cannot produce real results.
- Live progress polling every 2 s until `completed`/`failed` (`:78-97`).
- Results tab: severity filter chips, per-vuln cards, **JSON and CSV export** via `GET /api/scans/{id}/export` (`components/ScanResults.jsx:51-55`).
- Attack-paths tab: `components/AttackPathGraph.jsx` renders paths as **styled node/edge chip sequences, not an actual graph visualization** — no SVG, canvas, or graph library; nodes are colored `<div>`s by type (host/vulnerability/service).
- Scan history sidebar; favorite targets (add/list/delete).
- Deep-link support via `?scan=<id>`.

**RAG Assistant (`/rag`, `pages/RAGAssistant.jsx`, 169 lines)**
- Chat panel with user/assistant bubbles and a per-message collapsible **Sources** list (`components/ChatPanel.jsx:59+`).
- Four hardcoded starter prompts: *"What is CVE-2021-44228?"*, *"How to remediate Log4Shell?"*, *"List critical CVEs for Exchange"*, *"Attack vectors for Spring4Shell?"* (`ChatPanel.jsx:29-34`).
- Session sidebar — list, switch, delete; "New Chat" resets to a fresh `session_${Date.now()}`.
- LLM status banner from `GET /api/llm-status`: green "Local LLM Active: `<model>` via Ollama" or red "Local LLM Not Found" with an `ollama pull qwen2.5-coder:7b` hint.
- Footer showing indexed CVE count and `ChromaDB + <model> (Ollama)` / `ChromaDB (no LLM — fallback mode)`.

**CVE Browse (`/cve`)** — keyword search over descriptions, severity filter chips, exploit-only toggle, click-through to detail.
**CVE Detail (`/cve/:cveId`)** — CVSS/severity header, description, remediation, reference links, back navigation.
**Settings (`/settings`)** — LLM status card, scanner-availability health card, and a **live backend log viewer** polling `GET /api/logs` every 5 s (`Settings.jsx:29`).

**Orphaned component:** `components/MetricsPanel.jsx` renders "Evaluation Metrics" tiles for `detection_f1` / `bleu` / `rouge` — but **it is imported by no file** (verified by grep). There is no API endpoint serving those values either. The eval metrics are unreachable from the UI.

### Existing explanation/chat output

The RAG Assistant is the explanation feature. Its output shape is fully determined by `RAGPipeline.SYSTEM_PROMPT` (`rag_chain.py:40-59`), which instructs: answer from context; include specific CVE IDs, CVSS scores, and remediation steps; be "precise and technical"; acknowledge insufficient information; prioritize critical/high severity; provide "clear, structured answers" with "actionable remediation steps."

**No verbatim sample output exists anywhere in the repo** — no fixtures, no golden files, no tests, no transcripts in the docs. The closest artifact is the hardcoded BLEU *reference* string in `run_eval.py:43-48`, which is a hand-written target rather than a captured response:

> "CVE-2021-44228 is a critical remote code execution vulnerability in Apache Log4j2. The vulnerability has a CVSS score of 10.0. Attackers can exploit it by sending crafted log messages that trigger JNDI lookups. The recommended remediation is to upgrade Log4j to version 2.17.1 or later."

Twenty-five real assistant/user turns exist in `backend/data/vulndetect.db` (`chat_messages`) if actual sample output is needed for the paper — that is the only source of genuine system output in the repo.

Rendering is plain text: `<p className="... whitespace-pre-wrap">{msg.content}</p>` (`ChatPanel.jsx:56`). No markdown rendering, no syntax highlighting, no streaming — the reply appears in one block after the full completion returns.

### Instrumentation on user actions

**None.** No analytics library, no event logging, no client-side timing, no interaction timestamps. Grep for `analytics|gtag|posthog|mixpanel|track(|telemetry` across `frontend/src` returns exactly one hit: `anonymized_telemetry=False` in the ChromaDB config (`vector_store.py:150`) — i.e. telemetry being disabled, in backend code.

The only user-action timestamps that exist anywhere are incidental DB columns: `ChatMessageDB.created_at`, `ScanDB.started_at`/`completed_at`. Nothing reads them for measurement.

### Onboarding, skill-level detection, explanation-depth customization

**None of the three, anywhere in the UI or backend.** No first-run flow, no tour, no tooltips-as-onboarding, no user model, no expertise setting, no verbosity or depth control, no comprehension checks, no follow-up-question generation. The Settings page exposes only diagnostics (LLM status, scanner health, logs) — no user preferences at all. The system prompt is fixed and assumes a "security professional" audience ("*You are a cybersecurity expert assistant... Your role is to help security professionals*", `rag_chain.py:40`), i.e. the single hardcoded persona is the opposite of adaptive.

---

## 6. Everything else worth knowing

### Dependencies: declared vs. actually imported

`requirements.txt` (root, 17 packages) and `backend/requirements.txt` (same 17, no comments) are identical in content.

**Declared but never imported by project code:**

| Package | Status |
|---|---|
| `nltk` | **Unused.** BLEU/ROUGE are hand-implemented in `evaluators.py`. No import anywhere. |
| `aiofiles` | **Unused.** No import in project code. |
| `faiss-cpu` | Imported only inside `FAISSVectorStore` (`vector_store.py:299,315,338,390,407`), which is never selected (default is chroma) and is dimension-broken (§3). Effectively dead. |
| `numpy` | Imported only inside the same dead FAISS paths (`:314,337`). |
| `sentence-transformers` | Not imported directly; pulled in transitively by `langchain-huggingface`. Correct to declare, but not a direct dependency. |

**Used but not declared:**

| Package | Where | Note |
|---|---|---|
| `openai` | `llm_config.py:73` (OpenAI), `:167` (Groq — Groq uses the OpenAI SDK against its own base URL) | **Missing from requirements.** Selecting `LLM_PROVIDER=groq` or `openai` fails with `ImportError` on a clean install. The README advertises Groq as a supported cloud option and the Tech Stack table lists it. |
| `requests` | `llm_config.py:216,249`, `embedding_service.py:74,83` (HuggingFace paths) | **Missing.** Usually present transitively, but not declared. |
| `redis` | `conversation_memory.py:266` | Missing, though the Redis backend is opt-in and unreachable by default. |

Note the two paths are inconsistent: `httpx` (declared, used by Burp/ZAP) and `requests` (undeclared, used by the HF LLM/embedding paths) do the same job in the same codebase.

**Frontend** (`frontend/package.json`): `react`, `react-dom`, `react-router-dom`, `axios`, `lucide-react`, `recharts` — **all six are imported and used**; `recharts` only in `Dashboard.jsx`. Dev deps (vite, tailwind, postcss, autoprefixer, @vitejs/plugin-react, @types/*) are all in use. No unused frontend dependencies found.

The README claims v3.5 "Cleaned Dependencies: Removed 7 unused packages." Four unused packages remain (`nltk`, `aiofiles`, and effectively `faiss-cpu`/`numpy`), and two used ones are undeclared.

### Stubs, dead code, incomplete features

Project code is unusually clean of `TODO`/`FIXME` markers — a full grep across `backend/`, `rag_assistant/`, `scripts/`, and `frontend/src` (excluding `venv/` and `node_modules/`) finds **zero** `TODO`, `FIXME`, `XXX`, `HACK`, or `raise NotImplementedError`. The incompleteness is unmarked, which makes it easy to miss:

- `burp_scanner.py:210` — `raise Exception("Burp CLI automation not fully supported")`, with the preceding `cmd` list dead.
- `zap_scanner.py:276-280` — `_parse_cli_output` returns `[]` unconditionally.
- `openvas_scanner.py` / `nessus_scanner.py` — mock-only by construction.
- `embedding_service.py:160-197` — `chunk_text` implemented, never called.
- `vector_store.py:189` — computed `embeddings` discarded.
- `vector_store.py:404-420` — `FAISSVectorStore._load_index` defined, never called (indexes are written but never read back).
- `rag_engine.py:171-214` — `query_with_pipeline` unreachable (no route, no caller).
- `RAGEngine` itself is now largely bypassed: `routes_rag.py:12,21` imports `get_rag_pipeline` directly, so the `RAGEngine` wrapper is used only by `seed_cve_data.py` for indexing.
- `components/MetricsPanel.jsx` — orphaned (§5).
- `backend/data/exploitdb_sample.json` — loaded by nothing.
- `zap_scanner.py:251,267` and `burp_scanner.py:204` — hardcoded `/tmp/...` POSIX paths in a Windows-primary project.
- `frontend/src/api/client.js:5` — a 300 000 ms (5-minute) axios timeout, presumably for long scans, applied globally to every request including chat.

### Tests

**There is no test suite.** No `pytest`, no `unittest`, no `conftest.py`, no `*.test.jsx`, no CI config. Neither test runner is even declared as a dependency.

The single file matching a test naming pattern, `backend/test_sqlite_like.py` (30 lines), is a **manual scratch script**, not a test: it builds an in-memory SQLite DB with two rows and `print()`s the results of two `ilike` queries to demonstrate that SQLAlchemy's `escape="\\"` parameter is required for `%` escaping. It has no assertions and no test function — it verifies a one-line detail of `routes_cve.py:53`. Running it under pytest would collect nothing.

**Coverage is therefore 0%** across scanner parsing, aggregation/dedup, attack-path computation, the RAG pipeline, the API surface, and the frontend.

### Repository structure

```
vuln-detect-rag/
├── backend/
│   ├── api/              routes_scan.py (307L), routes_rag.py (140L), routes_cve.py (65L)
│   ├── models/           database.py (SQLAlchemy, 5 tables), schemas.py (Pydantic v2)
│   ├── scanners/         base.py (ScanVulnerability + ABC) + 6 adapters (~1470L total)
│   ├── services/         orchestrator, aggregator, rag_engine, attack_path, evaluators
│   ├── data/             sample_nvd.json (50 CVEs), exploitdb_sample.json (5, unused),
│   │                     vulndetect.db (SQLite), chroma/ (collection "cve_knowledge", 50 embeddings)
│   ├── venv/             committed virtualenv — BROKEN (base interpreter absent)
│   ├── main.py           FastAPI app, rate limiting, CORS, /health /llm-status /logs
│   └── config.py         pydantic-settings; APP_VERSION "3.5.0"
├── rag_assistant/        standalone RAG package
│   ├── llm_config.py     4 LLM providers + factory (385L)
│   ├── embeddings/       EmbeddingService + unused EmbeddingCache (253L)
│   ├── vectorstore/      Chroma + FAISS + factory (456L)
│   ├── chains/           RAGPipeline + 3 specialized subclasses (406L)
│   └── memory/           in-memory + Redis conversation memory (342L)
├── scripts/              run_eval.py (96L), seed_cve_data.py (73L), data/ (duplicate chroma store)
├── frontend/
│   ├── src/  api/ components/(9) pages/(6) context/ utils/    ~1900L
│   └── dist/             committed production build
├── EMET/                 UNTRACKED full duplicate — Netlify variant (see below)
├── v1.5/                 UNTRACKED full duplicate — older snapshot
├── README.md, research_paper.md (598L), project_explanation.md (750L), roadmap.md (61L)
└── Run_VulnDetect.bat / .sh
```

Total first-party source: roughly **7 500 lines** (≈5 600 Python, ≈1 900 JS/JSX), excluding the three duplicate trees, `venv/`, `node_modules/`, and `dist/`.

The `EMET/` duplicate is worth flagging: it is a **deployment variant with a materially different architecture** — `EMET/frontend/src/services/mockScanner.js` is a pure client-side scanner simulation (a `VULNS` array of hardcoded findings), and `EMET/frontend/src/api/groqClient.js` calls `api.groq.com/openai/v1/chat/completions` directly from the browser with `llama-3.3-70b-versatile` and a `VITE_GROQ_API_KEY`. It also ships `netlify.toml` and `_redirects`. **In that build, there is no Python backend, no local LLM, no vector store, and no real scanning at all.** If a live demo was ever shown from a Netlify URL, it was almost certainly this build — which shares no runtime code with the system described in `research_paper.md`.

### Git history and code recency

Repo has 6 commits, all on 2026-03-27/28, the last being `a3e4784 feat: release v2.0 with 100% local Ollama integration and privacy-first architecture` (2026-03-28 00:16 +0530).

**The working tree is far ahead of git and has been for months.** 42 paths are dirty: 25 modified, 7 untracked. Untracked items include entire features — `backend/scanners/burp_scanner.py`, `backend/scanners/zap_scanner.py`, `frontend/src/context/` (the theme system), `research_paper.md`, `Run_VulnDetect.sh` — plus the `EMET/` and `v1.5/` duplicate trees and a stray file literally named `nul` (a Windows artifact from a redirect to `NUL`).

`config.py:31` declares `APP_VERSION = "3.5.0"` and the README documents v3.5, but **nothing after v2.0 has ever been committed.** The v3.5 feature set — Burp, ZAP, the theme system, the security hardening the README enumerates — exists only in the working tree.

Recency by mtime: the actively-edited files are from **2026-05-05** (`orchestrator.py`, `config.py`, and five frontend pages). The rest of the tree dates to 2026-03-28. Nothing has been touched in roughly 3.5 months. The `.ruff_cache/` at the parent level suggests linting was run at some point, but no ruff config is committed.

---

## Summary of gaps vs. plan

Plain language, for the six items asked about. Each is **confirmed not built** unless qualified.

1. **Unified schema with conflict resolution — PARTIAL.** The unified schema *is* real and *is* used end to end: `ScanVulnerability` (`backend/scanners/base.py:6-21`), 12 fields, produced by all six adapters and carried through to the DB and API without bypass. Conflict resolution is the weak half — `aggregator.py:18-32` dedups by CVE ID and resolves CVSS disagreement by max-wins, merging only `references`. **Not built:** consensus or confidence weighting, provenance retention (the winner's `source_scanner` overwrites all others, so multi-scanner agreement is permanently lost), semantic reconciliation of conflicting descriptions/solutions/exploit flags, and any surfacing of conflicts to the API or UI.

2. **Real (non-mocked) OpenVAS/Nessus integration — CONFIRMED NOT BUILT.** Both files are ~70-85 lines that hardcode `is_available() → False` and return fixed, target-independent finding lists. No GVM/GMP client, no Tenable API client, no `.nessus` parsing. Both are nonetheless user-selectable in the scan UI with no indication they are simulated. *(Adjacent, and worth stating explicitly in any write-up: Burp's CLI path is a hardcoded raise and ZAP's CLI parser returns `[]`, so of six advertised scanners only **two — Nmap and Nuclei — will reach a real tool in a typical install**.)*

3. **Expert-graded evaluation set — CONFIRMED NOT BUILT.** No ground-truth file of any kind exists in the repo. `scripts/run_eval.py` never touches the RAG pipeline, the retriever, the LLM, or any scanner; all four inputs are Python literals in the script body. The F1 = 0.6667 and ROUGE = 0.4809 figures quoted in `research_paper.md`'s abstract are the arithmetic of those literals and are **invariant to the system's actual behavior**. This should be treated as the highest-priority gap for the paper.

4. **RAG ablation harness — CONFIRMED NOT BUILT.** No no-RAG baseline, no retrieval-off condition, no top-k sweep, no model or chunking comparison, no logging infrastructure to support one. The three alternate prompt pipelines that could seed a prompt ablation are unreachable (no route, no caller).

5. **User-study instrumentation — CONFIRMED NOT BUILT.** Zero analytics, event logging, or interaction timing in the frontend. Backend request latency is logged only at DEBUG (off by default), to a text file, never aggregated or persisted. No token counting, no cost tracking, no resource metrics. Only incidental DB timestamps exist, and nothing reads them.

6. **Explanation-depth / comprehension-check features in the RAG assistant — CONFIRMED NOT BUILT.** One fixed system prompt addressed to "security professionals," no user model, no expertise or verbosity setting, no onboarding, no comprehension checks, no adaptive follow-ups. The Settings page holds diagnostics only — there are no user preferences of any kind.

### Additional gaps found that were not on the list

- **The RAG pipeline is very likely retrieving nothing at runtime.** Two independent defects: the code queries collection `"vulnerabilities"` while the only populated on-disk collection is `"cve_knowledge"` (`config.py:39` is never read by `vector_store.py:118`), and `chromadb.Client(Settings(persist_directory=...))` does not enable persistence because `is_persistent` defaults to `False`. Verify interactively before making any grounded-retrieval claim. *(The persistence point is inferred for the pinned chromadb 0.6.3 — I confirmed the `is_persistent=False` default against an installed chromadb, but could not execute against the project's own venv, which is broken.)*
- **The RAG assistant cannot see scan results.** Only `sample_nvd.json` is ever indexed; `VulnerabilityDB` rows never reach the vector store. "Ask about the scan you just ran" is not a supported operation, which materially narrows what the system's RAG contribution actually is.
- **Write-side embeddings are discarded** (`vector_store.py:189`), so Chroma silently re-embeds with its own default function. Read and write agree only by coincidence of both defaulting to MiniLM; changing `EMBEDDING_PROVIDER` breaks similarity silently rather than loudly.
- **Chunking is implemented but never invoked** — each CVE is embedded whole.
- **No tests at all**, and no test runner declared.
- **`openai` is used but undeclared**, so the advertised Groq/OpenAI cloud paths fail with `ImportError` on a clean install.
- **v3.5 exists only in the working tree.** Git's last commit is v2.0; Burp, ZAP, the theme system, and `research_paper.md` are all untracked. There is no committed revision that matches what the README and the paper describe.
