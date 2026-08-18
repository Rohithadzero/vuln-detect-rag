# AUDIT REPORT V2 — Post-Remediation Verification

**Repository:** `vuln-detect-rag` (Emet)
**HEAD at audit time:** `ef632dd`
**Predecessor:** `AUDIT_REPORT.md` (retained unmodified as the "before" snapshot)
**Method:** every claim below was checked by reading current source or executing
current code. Commit messages, docstrings and prior session summaries were
treated as unverified assertions, not evidence. Where a docstring and the code
disagree, the code wins and the disagreement is reported.

---

## 1. Git state

**Working tree is effectively clean.** `git status --short` reports one modified
file, `backend/data/eval_results.json`, which is a generated artefact rewritten
by the evaluation harness. No source file is uncommitted.

**History is linear and readable from the pre-remediation snapshot forward.**
`b0ba232 chore: commit v3.5 working state prior to Phase 0.5 remediation` is the
"before" marker, and every subsequent commit is remediation work:

```
ef632dd feat(eval): add sharded condition; fix two measurement bugs it exposed
f9f341a docs: correct the token-saving claim from quadratic to linear
b200563 feat(rag): shard retrieved context across providers and verify answers
3651bfc docs: rewrite README for v4.0 and remove the last fabricated metrics
3525a90 feat(scanners): add six free professional tools (web + supply chain)
c7af8a5 feat(scanners): real OpenVAS adapter, working ZAP path, honest labelling
0862775 feat(eval): replace fabricated metrics with a real ablation harness
4400a53 feat: enrich the knowledge base, add scan briefings, research toggles
07d77dd feat(llm): add OpenRouter (free models only) and NVIDIA NIM providers
2050496 feat(llm): orchestrate Groq and Gemini in parallel, rotate across models
cde30e5 fix(rag): repair retrieval, index scan results, add Groq/Gemini
b0ba232 chore: commit v3.5 working state prior to Phase 0.5 remediation
```

**Quarantine: done.** `EMET/` and `v1.5/` are absent from the repository root
(`ls -d EMET v1.5` returns not-found) and present under `archive/`.
`.gitignore:71-73` excludes `archive/EMET/` and `archive/v1.5/` while
`archive/README.md` is tracked — `git ls-files` returns exactly
`archive/README.md` for that prefix. The directories therefore survive on disk
for reference but cannot be mistaken for canonical code in a fresh clone.

**`nul` still present and still ignored,** per the original instruction to ignore
rather than delete pending confirmation (`.gitignore:64-66`). It has not been
deleted. **This remains an open user decision.**

**No accumulated untracked files.** `git status --untracked-files=all` shows
nothing beyond the regenerated eval artefact.

### Finding 1.1 — a stray file predating the remediation is still tracked

`backend/test_sqlite_like.py` is a scratch script that builds an in-memory SQLite
table of two rows to probe `LIKE` behaviour. It imports nothing from the project,
asserts nothing, and is referenced nowhere. It is not a test despite the
filename. It was not in scope for any remediation section, so it is reported
rather than actioned.

---

## 2. Scanner scope

### OpenVAS — real adapter built, with a labelled mock fallback

`backend/scanners/openvas_scanner.py` contains a genuine GMP client, not a stub:

- `openvas_scanner.py:68` imports `gvm` to test availability
- `openvas_scanner.py:91-92` imports `TLSConnection`, `UnixSocketConnection` and
  `Gmp` from `python-gvm` — the real Greenbone protocol library
- `openvas_scanner.py:114-117` falls back to `_mock_scan(target)` **only** when
  credentials or the library are absent, and logs the reason
- `openvas_scanner.py:347` `_mock_scan` tags every entry
  `raw_output={"type": "mock"}` (lines 365, 379, 393, 407)

**Verdict: Done.** The live path is real; the fallback is labelled at the data
layer rather than in the UI, so the label cannot drift out of sync.

### Nessus — deliberately left simulated, correctly labelled

`backend/scanners/nessus_scanner.py:15-16` sets `free = False` and
`requires_licence = True` as class attributes, and `:27` returns `_mock_scan`
unconditionally. Every finding carries `raw_output={"type": "mock"}` (lines 43,
57, 71, 85, 98). The module docstring at `:10` states the intent explicitly.

**Verdict: Done as a decision** — no real adapter was built, because the free
tier is capped at 16 IPs behind registration. Honest labelling is present.

### Burp — the CLI stub is still a stub, but now an explicit, labelled one

`backend/scanners/burp_scanner.py:211-223` — `_scan_via_cli` still does not work.
It builds a command, then raises:

```python
        # Burp CLI is limited, return empty to fall back to mock
        raise Exception("Burp CLI automation not fully supported")
```

This is unchanged behaviour from the original audit. What *has* changed is the
surrounding honesty: `burp_scanner.py:32-33` sets `free = False` and
`requires_licence = True`, and the UI labels Burp as requiring a paid licence.

**Verdict: Partial.** The stub was not fixed. It is now disclosed rather than
concealed, which was the remediation instruction, but the code path remains dead
and still raises a bare `Exception` rather than a typed error.

### ZAP — `_parse_cli_output` removed, replaced with a real daemon path

The stub named in the original audit **no longer exists**. `grep -n
"_parse_cli_output"` returns nothing. In its place:

- `:293 _start_daemon()`, `:333 _await_daemon(timeout=120)`, `:354 _stop_daemon()`
- `:241 _scan_via_cli` now starts the daemon (`:255`), scans through the REST
  API, and stops it in a `finally` (`:259`)
- `:120 _scan_via_api` and `:178 _parse_api_results` handle an already-running
  daemon
- `:297` carries a comment recording why the old function was wrong — it
  "was never going to work"

**Verdict: Done.**

### Frontend marking of simulated results

Two independent layers, both verified:

1. **API level** — `backend/models/schemas.py:36` declares
   `simulated: bool = False` on the response model, and `:42-45` a
   `@model_validator` derives it from the finding payload:
   `object.__setattr__(self, "simulated", raw.get("type") == "mock")`.
   Labelling comes from the data, not from a UI hardcode.
2. **UI level** —
   - `frontend/src/components/VulnerabilityCard.jsx:38-43` renders a `Simulated`
     badge when `vuln.simulated`, tooltip
     `"Simulated sample data - this scanner did not run against the target"`
   - `frontend/src/components/ScanForm.jsx:22` marks Nessus `status: 'simulated'`
     with the note about the 16-IP cap; `:21` marks Burp `status: 'licence'`
   - `ScanForm.jsx:146-152` renders a pre-scan warning when any selected tool is
     not `live`

**Verdict: Done.**

---

## 3. RAG retrieval — the critical fix

### Collection-name mismatch: fixed

`rag_assistant/vectorstore/vector_store.py:126`

```python
DEFAULT_COLLECTION = os.getenv('CHROMA_COLLECTION', 'cve_knowledge')
```

`:143` passes `collection_name or DEFAULT_COLLECTION` to the base class. The
hardcoded `vulnerabilities` name is gone. `backend/config.py:42` sets
`CHROMA_COLLECTION = "cve_knowledge"` and `config.py:187` republishes it into
`os.environ`, so writer and reader resolve to the same string by construction
rather than by coincidence.

### `Client` vs `PersistentClient`: fixed

`vector_store.py:170-173`

```python
                    os.makedirs(self.persist_directory, exist_ok=True)
                    self._client = chromadb.PersistentClient(path=self.persist_directory)
                    logger.info("Using persistent ChromaDB at %s", self.persist_directory)
```

The docstring at `:157-160` records the failure mode precisely: `is_persistent`
defaults to `False`, so the old `Client(Settings(persist_directory=...))` form
was in-memory and every restart began from an empty collection.

### Embeddings passed at write time: fixed

`vector_store.py:215-232`

```python
            embeddings = [doc.embedding for doc in documents]
            ...
            if all(e is not None for e in embeddings):
                payload["embeddings"] = embeddings
            ...
            self.collection.upsert(**payload)
```

The all-or-nothing guard matters: a partially-embedded batch is not silently
half-written, and `upsert` makes re-indexing idempotent instead of duplicating
rows.

### Live test — executed during this audit

Run from the repository root against the real store:

```
collection: cve_knowledge | count: 190

===== RETRIEVED (4) =====
[Doc 1] score=0.9900 cve_id=CVE-2021-44228 source_type=cve_database
        title=CVE-2021-44228 - Apache Log4j2 versions 2.0-beta9 through 2.14.1 JNDI
   text: # CVE-2021-44228 - Apache Log4j2 versions 2.0-beta9 through 2.14.1 JNDI
         features used in... Identifier: CVE-2021-44228 Severity: CRITICAL
         (CVSS base score 10.0 out of 10) - critical risk, typically remotely
         exploitable with sever
[Doc 2] score=0.7978 cve_id=CVE-2021-45046 source_type=cve_database
        title=CVE-2021-45046 - It was found that the fix to address CVE-2021-44228 i
   text: # CVE-2021-45046 - ... Severity: CRITICAL (CVSS base score 9.0 out of 10)
[Doc 3] score=0.7942 cve_id=CVE-2022-47966 source_type=cve_database
   text: CVE-2022-47966 (CRITICAL, CVSS 9.8) Description: Multiple Zoho ManageEngine
         products are affected by a Remote Code Execution vulnerability due to the
         usage of an outdated third-party dependency, Apache Santuario.
[Doc 4] score=0.7851 cve_id=CVE-2023-44487 source_type=cve_database
   text: # CVE-2023-44487 - The HTTP/2 protocol allows a denial of service
```

This is **real retrieved content**, not a fallback:

- 190 chunks are present in the collection, so persistence survives restarts.
- The exact-ID hit scores 0.9900 — the hybrid lookup's authoritative pin — while
  semantic neighbours score 0.78 to 0.80. A genuine distribution, not a constant.
- `CVE-2021-45046`, the follow-up Log4j CVE, ranking second is evidence the
  embeddings carry real semantic structure rather than noise.
- The text contains real NVD prose and real CVSS values.

**Scope note.** The generated *answer* could not be captured in the same run: an
evaluation harness was concurrently occupying every cloud provider's rate limit,
and a generation attempt timed out at 120 s. Retrieval was therefore verified in
isolation. Generation was separately observed working during the same session
(Section 5), but this report does **not** claim a verified end-to-end answer
capture for CVE-2021-44228 specifically.

### `metadata.source_type` / `metadata.title`: fixed

Visible in the live output above: `source_type=cve_database` on every hit, and
`title` carrying the real CVE summary line. Neither `unknown` nor `Untitled`
appears. `rag_assistant/chains/rag_chain.py:187-188` still applies
`setdefault('source_type', 'unknown')` and `setdefault('title', base_id)` as a
floor, but the enrichment path populates both before that point is reached.

---

## 4. Scan-result indexing

**Added, and wired into the scan lifecycle.**

- `backend/services/rag_engine.py:454` defines
  `index_scan_results(self, scan_id, target, vulnerabilities) -> int`.
- `backend/services/orchestrator.py:98` calls `await self._index_results(...)`
  inside `run_scan`, at `progress=90`, between aggregation and completion.
- `orchestrator.py:134-160` runs it in the thread executor — embedding is
  CPU-bound and would otherwise stall the event loop — and swallows failures with
  a logged exception, so an indexing fault cannot fail a scan whose results are
  already persisted.

**Metadata tagging: present.** `rag_engine.py:551` sets
`"source_type": "scan_result"`, distinct from `:228`'s
`"source_type": "cve_database"`. `RAGQuery.source_type` (`rag_chain.py:57`)
allows retrieval to be restricted to either corpus.

**Verdict: Done.**

---

## 5. Evaluation script

### `run_eval.py` — now calls the live pipeline

The hardcoded-literal version is gone. `scripts/run_eval.py` executes real
conditions against the real pipeline: `run_condition` dispatches to
`pipeline.retrieve(...)` for the retrieval-only arm and `pipeline.query(...)` for
the generation arms. Four conditions now exist — `sharded`, `full`, `no_rag`,
`retrieval` — with `SHARDING_BY_CONDITION` toggling `RAG_MAP_REDUCE` per arm.

Verified by execution: a run completed during this session and wrote
`backend/data/eval_results.json`, reporting live provider names, per-query
latencies in the tens of seconds, and token counts. All of these vary between
runs and therefore cannot be constants.

### `research_paper.md` — partially updated; one fabricated figure survives

The abstract (line 5) and Section 7 (line 529) **have** been replaced with the
measured ablation — ROUGE 0.0612 to 0.3591, CVE fidelity 0.00 to 0.81,
fabricated IDs 16 to 3, refusals 0/5 to 3/5 — and carry an explicit
preliminary-results caveat. The results table at lines 342-345 is real.

#### Finding 5.1 — the comparison table still contains the original fabricated numbers (HIGHEST SEVERITY)

`research_paper.md:382`

```
| **VulnDetectRAG** | 0.67 F1 (RAG), 0.48 ROUGE | **Yes** | **Yes** |
```

`0.67` and `0.48` are the rounded forms of the discredited `0.6667` F1 and
`0.4809` ROUGE identified in the original audit. They sit in the table comparing
this system against ProveRAG, CyberRAG and Vul-RAG — the most citation-visible
table in the paper. The README was cleaned of these values; the paper was not.

#### Finding 5.2 — the paper's central architectural claim is now false

Multiple passages still describe the system as local-only:

- `:5` — "powered by 100% local Large Language Models (LLMs) via Ollama ...
  running enterprise-grade vulnerability detection entirely offline without
  external API dependencies"
- `:42` and `:444` — "First privacy-first RAG implementation ... operating
  entirely offline without external API dependencies"
- `:384` — "VulnDetectRAG operates entirely offline"
- `:423`, `:433` — comparison tables asserting "100% local" AI and data privacy

Current default behaviour contradicts all of these (Section 6). The paper also
still says "six major security scanners" (`:5`) and names
`llama-3.1-70b-versatile` as the Groq model (`:143`); both are stale.

### `MetricsPanel.jsx` — wired to a real endpoint

`frontend/src/components/MetricsPanel.jsx:3` imports `getEvalMetrics` from
`../api/client`, and `:28` calls it from a `useEffect`. The backend route exists
at `backend/main.py:499` (`@app.get("/api/eval-metrics")`), reading
`eval_results.json` at `:508`. The component is no longer orphaned.

**Verdict: Partial** — script and panel done; the paper is not fully cleaned.

---

## 6. Multi-backend / cloud LLM work (new scope since last audit)

### Real adapters, not placeholders

`rag_assistant/llm_config.py` defines genuine HTTP clients for all four:

| Class | Line | Notes |
|---|---|---|
| `GeminiClient(RemoteModelResolverMixin, BaseLLMClient)` | 639 | Native Gemini REST shape |
| `GroqClient(RemoteModelResolverMixin, BaseLLMClient)` | 921 | OpenAI-compatible `/chat/completions` |
| `OpenRouterClient(GroqClient)` | 1135 | Inherits the Groq dialect |
| `NvidiaClient(GroqClient)` | 1240 | Inherits the Groq dialect |

Each implements `generate_detailed`, `stream`, `chat_with_tools` and live model
resolution. These are working adapters, not config stubs.

### Backend selection is orchestration, not a single-choice toggle

The most significant scope change since the original audit. The routing code,
`llm_config.py` in `get_llm_client()`:

```python
    cloud = get_cloud_clients()
    local = get_local_clients()
    ...
    tiers: List[BaseLLMClient] = []
    if cloud:
        if len(cloud) > 1 and ensemble_enabled:
            tiers.append(EnsembleLLMClient(cloud))
    ...
    if local:
        tiers.extend(local)
    ...
    return FallbackLLMClient(tiers)
```

Three composition layers, all active by default:

1. **`ModelRotatingClient`** (`:1748`) — within one provider, walks its entire
   model catalogue, putting a failed model on a 300 s cooldown.
2. **`EnsembleLLMClient`** (`:1884`) — queries multiple cloud providers *in
   parallel* and reconciles their answers with a further synthesis call.
3. **`FallbackLLMClient`** (`:2097`) — descends tiers when a whole tier fails.

Added in `b200563`, a fourth mode supersedes the ensemble by default:
`ShardedReader` (`rag_assistant/chains/map_reduce.py`) partitions retrieved
documents across providers so each reads a different slice, then merges the
extracts. `rag_chain.py` selects it when there are at least 3 documents and at
least 2 configured cloud providers.

**A single user question can therefore dispatch to four different companies'
APIs.**

### Ollama is no longer the default

`backend/config.py:46-49`

```python
    LLM_PROVIDER: str = "auto"
    LLM_PROVIDER_ORDER: str = "groq,gemini,openrouter,nvidia,ollama"
    LLM_FALLBACK: bool = True
```

Ollama is **last** in preference order. With any cloud key configured, `auto`
resolves to cloud. `config.py:86` also sets `LLM_ENSEMBLE: bool = True`.

**Configuration inconsistency:** the root `.env.example:3` still says
`LLM_PROVIDER=ollama`, while `backend/.env.example:9` says `LLM_PROVIDER=auto`
with order `groq,gemini,ollama`. `config.py:131-134` reads both files with
`backend/.env` taking precedence, so the root file's local-first default is
misleading to anyone who copies it.

### Finding 6.1 — no privacy disclosure anywhere in the UI (HIGH)

A grep across `frontend/src/components/*.jsx` and `frontend/src/pages/*.jsx` for
`privacy|leaves your machine|sent to|off-machine|data leaves|third.?party`
returns **zero matches**.

The closest text is `ProviderControls.jsx:216-219`, which describes the mechanism
but never its consequence:

```jsx
      <p className="text-[10px] font-bold text-gray-500 uppercase">
        Enabled cloud providers are queried in parallel and their answers reconciled.
        Ollama is used only when every cloud provider is unreachable.
      </p>
```

A user reading this learns that providers are "queried in parallel". They are
never told that their scan findings — hostnames, open ports, and discovered
vulnerabilities on infrastructure they may not own — are transmitted to Groq,
Google, OpenRouter and NVIDIA. **Backend switching is currently silent with
respect to data handling.**

### Finding 6.2 — cloud backends are exercised automatically, with no user action (HIGH)

This directly contradicts the "local-first" claim. Three independent automatic
paths:

1. **Default resolution.** `LLM_PROVIDER=auto` plus a cloud-first order means the
   first run with any key present goes to cloud without a prompt.
2. **Automatic fallback.** `LLM_FALLBACK=True` means `FallbackLLMClient` descends
   tiers on failure. The tier order places cloud above local, so the descent is
   local-*last*, never local-first.
3. **Scan-completion briefings.** `orchestrator.py:98` indexes results and the
   scan-explain path generates an AI briefing — an LLM call triggered by
   *finishing a scan*, not by the user asking a question. Under default settings
   that call goes to a cloud provider.

The `disabled_providers` mechanism (`llm_config.py`, backed by
`LLM_DISABLED_PROVIDERS`) and `main.py:250-261`'s persisted preferences do let a
user switch providers off — but the **default is on**, and the opt-out is only
discoverable by visiting Settings.

**For the paper this is decisive.** The "privacy-first, 100% local" framing
describes a configuration that is no longer the default, and the code contains no
consent gate. Either the default must change or the claim must be withdrawn.

---

## 7. Dependency and cleanup items

### `requirements.txt`

- **`requests`: declared** — present, with a comment recording that all four
  cloud providers, the Ollama client, and the KEV/EPSS/NVD feeds depend on it.
- **`openai`: correctly *not* a hard dependency** — documented as optional, needed
  only for `LLM_PROVIDER=openai`, because Groq and OpenRouter are reached over
  plain HTTP. This is the right call, and it is now explained rather than left
  ambiguous.
- **`redis`: documented as optional**, needed only for
  `get_conversation_memory(backend="redis")`.
- **`nltk`, `aiofiles`, `ollama`: removed**, with a "Removed in v3.5 remediation"
  block stating why — nltk never imported, because BLEU and ROUGE are
  hand-implemented in `backend/services/evaluators.py`; aiofiles never imported;
  ollama superseded by direct REST calls.

**Verdict: Done.** *Minor:* the file header still reads "VulnDetectRAG v3.5"
while the app reports `4.0.0` (`config.py:31`).

### Hardcoded `/tmp/` paths

A repo-wide grep for `/tmp/` string literals across `backend/`, `rag_assistant/`
and `scripts/` returns **no project matches** — only vendored packages under
`backend/venv/`. Replacements verified:

- `backend/scanners/zap_scanner.py:264` —
  `os.path.join(tempfile.gettempdir(), "zap_report.json")`, with `:261-263`
  explaining the Windows portability reason
- `backend/scanners/burp_scanner.py:219` —
  `os.path.join(tempfile.gettempdir(), "burp_scan.burp")`
- `backend/scanners/web_tools.py:70, 184, 259` — same pattern, PID-suffixed
- `rag_assistant/vectorstore/vector_store.py:381` — FAISS index path

**Verdict: Done.**

### `chunk_text`

Defined at `rag_assistant/embeddings/embedding_service.py:285`
(`chunk_size=900, overlap=150`) and **invoked** at
`rag_assistant/chains/rag_chain.py:238`:

```python
                self.embedding_service.chunk_text(content) if chunk else [content]
```

No longer dead code. **Verdict: Done.**

---

## 8. Tests and instrumentation

**No tests were added.** Excluding `backend/venv/`, `frontend/node_modules/` and
`archive/`, the only matching file is `backend/test_sqlite_like.py` — the scratch
script from Finding 1.1, which contains no assertions and tests nothing in this
project. There is no `tests/` directory, no pytest configuration, and no frontend
test setup.

This is unchanged from the original audit and was not in any remediation section.
It remains the largest structural gap: roughly 1,300 lines of new orchestration
logic (`llm_config.py`, `map_reduce.py`, `grounding.py`) were added during
remediation with **zero** automated coverage. Two bugs found late in the session
by manual observation — a verifier that silently checked nothing because models
emit non-breaking hyphens, and a parallel-dispatch timeout that discarded good
answers — are precisely the class of defect a unit test catches immediately.

**No user-study instrumentation.** A grep for
`analytics|telemetry|track(|logEvent|timestamp` across `frontend/src/` returns
nothing. There is no event logging, no timing capture, and no interaction record.
Any user study described in the paper would currently have no data source.

---

## Table A — Remediation status (REMEDIATION_PROMPT.md Sections 1-6)

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Commit working tree, clean history from snapshot | **Done** | HEAD `ef632dd`; `b0ba232` snapshot; only a generated artefact modified |
| 1 | Quarantine `EMET/` and `v1.5/` | **Done** | Both under `archive/`; `.gitignore:71-73`; only `archive/README.md` tracked |
| 1 | Leave `nul` alone, ignore only | **Done** | `.gitignore:64-66`; file still present — *user decision still open* |
| 2 | Decide OpenVAS scope | **Done** | Real GMP adapter, `openvas_scanner.py:91-92`; mock only on missing creds |
| 2 | Decide Nessus scope | **Done** | Deliberately simulated; `free=False`, `requires_licence=True` at `:15-16` |
| 2 | Fix Burp CLI stub | **Partial** | `burp_scanner.py:222` still `raise Exception(...)`; now labelled paid-licence |
| 2 | Fix ZAP `_parse_cli_output` | **Done** | Function removed; daemon lifecycle at `:293`, `:333`, `:354` |
| 2 | Flag simulated results in UI | **Done** | `schemas.py:42-45` validator, `VulnerabilityCard.jsx:38-43`, `ScanForm.jsx:146-152` |
| 3 | Collection-name mismatch | **Done** | `vector_store.py:126`; `config.py:42,187` |
| 3 | `PersistentClient` | **Done** | `vector_store.py:170-173` |
| 3 | Embeddings at write time | **Done** | `vector_store.py:215-232`, all-or-nothing guard plus `upsert` |
| 3 | Live retrieval verified | **Done** | 190 chunks; CVE-2021-44228 at 0.9900 with real NVD text (Section 3) |
| 3 | `source_type` / `title` populated | **Done** | `source_type=cve_database`, real titles in live output |
| 4 | Index scan results into vector store | **Done** | `rag_engine.py:454`; called at `orchestrator.py:98`, progress 90 |
| 4 | Tag with distinguishing metadata | **Done** | `rag_engine.py:551` `source_type="scan_result"` |
| 5 | Replace `run_eval.py` | **Done** | Live `pipeline.query()` / `retrieve()`; four conditions; verified by execution |
| 5 | Remove fabricated numbers from paper | **Partial** | Abstract and Section 7 fixed; **`research_paper.md:382` still `0.67 F1, 0.48 ROUGE`** |
| 5 | Wire or remove `MetricsPanel.jsx` | **Done** | `MetricsPanel.jsx:3,28` to `/api/eval-metrics` (`main.py:499`) |
| 6 | Declare `requests` / `openai` / `redis` | **Done** | `requests` required; other two documented optional with rationale |
| 6 | Remove `nltk` / `aiofiles` | **Done** | Removed, with justification block |
| 6 | Fix `/tmp/` paths | **Done** | `tempfile.gettempdir()` at all four project sites; zero project matches |
| 6 | `chunk_text` invoked or removed | **Done** | Invoked at `rag_chain.py:238` |

---

## Table B — Scope changes since last audit

| Change | User-facing or evaluation-only? | Paper section | Note |
|---|---|---|---|
| Four cloud providers (Groq, Gemini, OpenRouter, NVIDIA) with real HTTP adapters | **User-facing, default-on** | System design + Threats to validity | Invalidates the "100% local" claim as written |
| `ModelRotatingClient` — per-provider catalogue rotation with cooldowns | User-facing (invisible) | System design | Resilience mechanism; hurts reproducibility, since the serving model varies per query |
| `EnsembleLLMClient` — parallel multi-provider query plus synthesis | User-facing | System design | Superseded as default by sharded reading; retained as the eval baseline |
| `ShardedReader` map-reduce — context split across providers | User-facing, **now default** | System design + Results | Measured 5.2x lower peak per-provider tokens, roughly 8x faster than broadcast |
| `grounding.py` — deterministic post-hoc claim verification | User-facing (caveats shown) + evaluation | Method + Results | No LLM call; checks CVE, CWE, CVSS and citations |
| One-pass grounding repair | User-facing | Method | Accepted only if the rewrite verifies better than the original |
| KEV / EPSS / NVD 2.0 / OSV enrichment | User-facing | System design | Free, no key required |
| Scan-result indexing plus AI scan briefings | User-facing | System design | LLM call triggered by scan completion, not by a user question |
| Six free tools (Nikto, testssl/sslyze, WhatWeb, Trivy, OSV-Scanner, Grype) | User-facing | System design | Paper still says "six scanners"; the actual total is twelve |
| Per-provider toggles, model selector, RAG on/off | User-facing | Method (ablation controls) | Enables the no-retrieval baseline from the UI |
| `simulated` flag on every finding | User-facing | System design + Limitations | Derived from data, not hardcoded in the UI |
| Evaluation: four conditions plus per-provider token accounting | Evaluation-only | Results | `sharded` and `full` differ only in `RAG_MAP_REDUCE` |

---

## Priority actions

1. **`research_paper.md:382` — delete `0.67 F1 (RAG), 0.48 ROUGE`.** These are the
   fabricated figures the first audit flagged, sitting in the paper's headline
   comparison table. Highest severity, because it is the most likely number a
   reviewer will cite.
2. **Reconcile the privacy claim with the code.** Either flip the default to
   local-first, or rewrite every "100% local / entirely offline" passage
   (`:5`, `:33`, `:42`, `:78`, `:384`, `:423`, `:433`, `:444`). The current text
   describes a non-default configuration.
3. **Add a privacy disclosure to the UI** before any cloud provider transmits scan
   data. Nothing in the frontend currently tells a user their findings leave the
   machine.
4. **Update stale paper facts:** "six scanners" to twelve;
   `llama-3.1-70b-versatile` to the current default; `requirements.txt` header
   v3.5 to v4.0.
5. **Add tests** for `map_reduce.py`, `grounding.py`, and `llm_config.py`
   dispatch. Both late-session bugs were of a kind unit tests catch instantly.
6. **Resolve the two open user decisions:** delete `nul`? track `archive/`?
7. **Rotate the four exposed API keys** if not already done.

---

*Prepared by reading source at `ef632dd` and executing the retrieval path live.
Where a claim could not be verified in this session it is marked as such rather
than inferred.*
