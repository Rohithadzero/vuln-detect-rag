# Centralized Vulnerability Detection & Intelligent Query (RAG)

![Version](https://img.shields.io/badge/version-v4.5-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Node](https://img.shields.io/badge/node-18.x-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macOS-lightgrey)

A unified vulnerability scanning platform with RAG-powered intelligence across **twelve security tools** — network, web and supply chain — with answers grounded in a live-enriched CVE knowledge base.

The AI layer **splits the retrieved evidence across four free cloud providers** (Groq, Google Gemini, OpenRouter, NVIDIA NIM) so each reads only its own share, then merges their extracts into one cited answer — and falls back to a **fully local Ollama** model when every cloud provider is unreachable. Every finished answer is checked back against the retrieved text before it is returned.

## Architecture

```text
  User picks a target and tools
              │
              ▼
  ┌───────────────────────────────────────────────────────────┐
  │  12 scanner adapters                                      │
  │  Network : Nmap · Nuclei · OpenVAS(GMP)                    │
  │  Web     : ZAP · Nikto · testssl/sslyze · WhatWeb          │
  │  Supply  : Trivy · OSV-Scanner · Grype                     │
  │  Paid    : Burp(licence) · Nessus(simulated)               │
  └───────────────────────────────────────────────────────────┘
              │  every adapter emits the same ScanVulnerability
              ▼
  Aggregation ── dedupe by CVE, merge references, normalise severity
              │
              ▼
  Enrichment ── CISA KEV · FIRST EPSS · NVD 2.0 · OSV   (free, no key)
              │
              ▼
  Chunk → embed (local MiniLM) → ChromaDB          [RAG toggle: on/off]
              │
              ▼
  ┌───────────────────────────────────────────────────────────┐
  │  Hybrid retrieval: exact CVE-ID lookup + semantic search,  │
  │  score threshold, per-CVE dedupe, grounding guard          │
  └───────────────────────────────────────────────────────────┘
              │
              ▼
  Retrieved docs are numbered [Doc 1..N] once, then split into shards
              │
              ▼
  ┌───────────────────────────────────────────────────────────┐
  │  MAP — each provider reads only its own shard, in parallel │
  │                                                            │
  │    docs 1-2  ──▶ Groq        ─┐                            │
  │    docs 3-4  ──▶ Gemini       │  "extract only what these  │
  │    docs 5-6  ──▶ OpenRouter   │   docs support, or reply   │
  │    docs 7-8  ──▶ NVIDIA      ─┘   NOTHING_RELEVANT"        │
  │                                                            │
  │  each provider rotates across its whole model catalogue    │
  └───────────────────────────────────────────────────────────┘
              │  extracts only — never the raw documents
              ▼
  ┌───────────────────────────────────────────────────────────┐
  │  REDUCE — one small call merges the extracts into an       │
  │  answer, preserving the original [Doc N] citations         │
  │                                                            │
  │  Ollama (local) — only when every cloud provider fails     │
  └───────────────────────────────────────────────────────────┘
              │
              ▼
  ┌───────────────────────────────────────────────────────────┐
  │  VERIFY — every CVE ID, CWE ID, CVSS score and [Doc N]     │
  │  citation checked against the retrieved text. No LLM call. │
  │  Unsupported claims → one repair pass, else a visible      │
  │  caveat appended to the answer.                            │
  └───────────────────────────────────────────────────────────┘
              │
              ▼
  Plain-language briefing, with verified [Doc N] citations
```

## What's New in v4.5

**Structural knowledge graph (CVE → CWE → CAPEC → ATT&CK).** A CVE record
tells you what is broken. It does not tell you what an adversary could do with
it. v4.5 joins the corpus to the MITRE cross-references that answer that:

```
CVE-2021-44228  →  CWE-502 (deserialization of untrusted data)
                →  CAPEC-586, CAPEC-13, CAPEC-23, …
                →  T1027, T1574.006, T1553.002, …  (8 techniques)
```

2272 nodes, 3239 edges. **Every edge is a published MITRE or NVD
cross-reference — none is inferred by a model**, so the graph adds structure
without adding claims.

- `dataset/` holds the sources, with `MANIFEST.json` recording the URL and
  SHA-256 of each. `python scripts/fetch_datasets.py` downloads them;
  `python scripts/build_knowledge_graph.py --stats` builds the graph.
- Held in memory, not in Neo4j — the system runs with no external services and
  every query is a one- or two-hop walk. `knowledge_graph.cypher` is exported
  anyway so that is a default, not a lock-in.
- The RAG pipeline appends graph structure to the prompt, keyed on the
  documents **retrieval actually returned** rather than on the question. Keying
  on the question would let a query about an absent CVE pull in taxonomy the
  model could build a confident answer from, turning a correct refusal into a
  fabrication. Disable with `RAG_GRAPH_CONTEXT=0`.
- New **Knowledge Graph** page and `/api/graph/*` endpoints.

Coverage is reported honestly: 48 of 50 corpus CVEs carry a CWE, but only **19
reach an ATT&CK technique**. The chain breaks where CAPEC has no pattern for
that weakness. A CVE whose walk ends early is shown as having no mapped
patterns rather than padded.

**Dashboard fix.** The dashboard went blank the moment its data arrived.
`useMemo` was called *after* the `loading` and `error` early returns, so the
hook count changed between the first render and the second and React aborted
with "rendered more hooks than during the previous render". The hook now runs
unconditionally, above both returns.

## What's New in v4.1

A dependency pin silently disabled the knowledge base.

`requirements.txt` allowed `chromadb<1.0.0`, so a fresh environment installed
0.6.3. The store in `backend/data/chroma` had been written by a 1.x client: its
collection row carries an empty `config_json_str` at schema migration 18, while
the 0.x loader requires a legacy `_type` key. Every read raised
`KeyError: '_type'`.

The data was never lost — all 190 embeddings sat intact on disk the entire time.
The client simply could not open them, so retrieval returned zero documents and
the assistant answered from the model's own memory. That is precisely the
failure this project exists to prevent, and it presented as a working app.

The pin now requires `chromadb>=1.0.0,<2.0.0`, which reads the existing
directory unchanged. Nothing was migrated or deleted.

### The seeder was reporting success it had not achieved

`scripts/seed_cve_data.py` called `index_cves()`, discarded the count it
returned, and printed `len(cve_entries)` unconditionally. A run in which every
single write failed still finished with `Indexed 50 entries into ChromaDB`
directly beneath the errors that had just scrolled past.

It now prints the count `index_cves` actually returned, and exits non-zero when
that count is zero — a state both launchers already surface as a warning that
the assistant has no corpus to retrieve from.

The general lesson is the same one the grounding verifier taught in v4.0: a
check that cannot report failure is worse than no check, because it converts an
outage into a false assurance.

## What's New in v4.0

This release began as an audit (`AUDIT_REPORT.md`) and turned into a substantial
repair. The headline finding was that **RAG retrieval returned nothing at all**,
and the published evaluation numbers were not measurements.

### Retrieval actually works now

Three independent defects meant the assistant never saw a single retrieved
document, and answered every question from the model's own memory:

1. **Collection mismatch** — the writer populated `cve_knowledge` while the
   reader queried a hardcoded `vulnerabilities`, so retrieval always hit an
   empty collection.
2. **Persistence disabled** — `chromadb.Client(Settings(persist_directory=…))`
   is in-memory; `is_persistent` defaults to `False`. Now `PersistentClient`.
3. **Embeddings discarded on write** — vectors were computed and then never
   passed to Chroma, which silently re-embedded with a different function, so
   queries and documents lived in different vector spaces.

### Retrieval quality

- **Hybrid retrieval** — exact CVE-ID metadata lookup runs alongside semantic
  search, because an embedding of `CVE-2021-44228` is nearly indistinguishable
  from any other CVE ID.
- **Grounding guard** — with no usable context the assistant says so instead of
  inventing an answer. Answers cite `[Doc N]`.
- **Per-CVE dedupe and a score threshold**, so five chunks of one document
  cannot crowd out five distinct findings.
- **Chunking is actually invoked** (it was dead code), and conversation history
  is no longer truncated to 200 characters mid-sentence.

### A knowledge base worth retrieving from

Indexed documents carried only a description and a CVSS score. Now enriched
from four free, no-key sources — **CISA KEV** (confirmed in-the-wild
exploitation and ransomware use), **FIRST EPSS** (exploitation probability),
**NVD 2.0** (CWE class, CVSS vector, attack vector, affected products) and
**OSV**. The assistant can now prioritise by what is actually being exploited
rather than by CVSS alone.

### Scan results are answerable

Scan findings were never indexed, so the assistant was blind to the scan you
had just run. They are now chunked, enriched and indexed, tagged
`source_type="scan_result"`, with a **plain-language AI briefing** for any
completed scan (bottom line → fix first → everything else → caveats).

### Sharded reading: the context is split, not broadcast

The first attempt at multi-provider orchestration asked every provider the
*same* question with the *same* full context and merged the answers. That was a
mistake in both directions:

- **It made rate limiting worse.** Four providers each read the entire context,
  so answering one question cost `4 × context` tokens and burned four free
  tiers four times as fast as one — while adding no new evidence, since every
  member read identical text.
- **It did not help accuracy.** A single prompt carrying every retrieved
  document asks one model to attend to all of them at once, and recall of any
  individual fact degrades as the surrounding context grows. Facts in the
  middle documents are exactly the ones a model papers over from memory.

Retrieved documents are now **partitioned across the providers** instead. Each
reads only its own shard and is asked one narrow question — *extract what these
documents support, or reply `NOTHING_RELEVANT`* — and a small **reduce** call
merges the extracts into the final answer.

- **Rate limiting** — each provider is charged for roughly `context / N` tokens
  instead of the whole context. Against the broadcast ensemble that is an
  `N`-fold reduction in tokens billed to any single provider (`C` → `C/N`), and
  an `N`-fold reduction in total tokens spent per question (`N·C` → `C`, plus
  one small reduce call). The saving is linear in the provider count, not
  quadratic.
- **Hallucination** — extraction over a handful of documents is a far easier
  task to do faithfully than open-ended synthesis over a wall of text, and the
  reduce step **never sees raw retrieved text at all**. It only sees extracts
  that already carry citations, so it has less opportunity to invent and
  nothing to invent from.
- **Latency** — shards for different providers run concurrently. Shards for the
  *same* provider run sequentially, deliberately: firing them together would
  spike that provider's requests-per-minute and trigger the very 429s this
  design exists to avoid.

Document numbers are assigned **globally, once, before sharding**, so a
`[Doc 7]` citation written by whichever provider happened to read document 7
still points at document 7 in the source list the user sees.

Sharding is skipped when it would not pay for its reduce call: fewer than three
documents, no retrieved context, or fewer than two configured cloud providers.
Each provider still **rotates across its entire model catalogue**, so a
rate-limited or retired model degrades the answer instead of breaking it, and
Ollama remains the offline last resort. Cloud-tagged Ollama models are never
auto-selected, since they would send scan data off-machine.

### Answers are verified against their evidence

The grounding rules in the system prompt are an instruction, not a guarantee: a
model can be told five times to answer only from the context and still emit a
CVE ID it remembers from pre-training. Every finished answer is now checked
against the retrieved text **deterministically, without an LLM call**:

- **Fabricated identifiers** — every CVE and CWE ID in the answer must appear in
  the retrieved documents.
- **Fabricated scores** — CVSS values are checked wherever the answer explicitly
  labels a number as a score, so prose numbers and ports are never mistaken for
  one.
- **Fabricated provenance** — a `[Doc 9]` citation when only six documents were
  supplied is a fabricated source, and is caught as one.

An answer with unsupported claims gets **one** corrective pass that strips them,
accepted only if the rewrite actually verifies better than the original;
otherwise a **visible caveat** is appended naming the specific unsupported
values. An unverifiable claim the reader believes is worse than a caveated one.

Free-text claims are deliberately *not* checked. Any string-matching heuristic
over prose produces more false alarms than findings, and a noisy verifier gets
ignored. The grounding report is returned in the response metadata, so the
evaluation harness can measure it rather than taking the answer's word for it.

### Honest evaluation

`scripts/run_eval.py` computed BLEU and ROUGE over **hardcoded string
literals** — it never called the retriever, the vector store or the LLM, so its
output was a constant. Replaced with a real harness (three ablation conditions,
retrieval metrics, groundedness, refusal rate, latency and token cost). The
fabricated F1/ROUGE figures have been removed from the README and the paper.

### Twelve tools, honestly labelled

Six free tools added — **Nikto**, **testssl/sslyze**, **WhatWeb**, **Trivy**,
**OSV-Scanner**, **Grype** — plus a **real OpenVAS/GMP adapter** and a working
ZAP daemon path. Simulated findings are now flagged per finding in the API and
UI; Burp is labelled as requiring a paid licence rather than presented as free.

### Research controls

Settings exposes a toggle per provider, a live model selector, and a **RAG
on/off switch**, so a backend can be isolated and the no-retrieval baseline
measured from the UI.

<details>
<summary>Previous Updates</summary>

### v3.5
- Neobrutalist UI redesign with Classic/Color theme toggle
- Burp Suite and OWASP ZAP scanner adapters
- Security hardening: XXE fix via `defusedxml`, CORS tightening, target
  validation before subprocess execution, bound to `127.0.0.1`
- Launcher script fixes for Windows and Linux/macOS

### v2.0
- Full Ollama Integration with 100% local AI
- Smart Model Auto-Detection
- Single-Click Execution via `Run_VulnDetect.bat`
- Unified RAG Engine

### v1.3
- Migrated to `langchain-huggingface` core embeddings
- Fixed metrics display errors, dynamic CVE counting

### v1.2
- Live Nmap & Nuclei scanning integration
- CVSS real-time extraction
</details>

## Core Features

- **12 security tools, one schema** — Nmap, Nuclei, OpenVAS, OWASP ZAP, Nikto,
  testssl/sslyze, WhatWeb, Trivy, OSV-Scanner, Grype (all free), plus Burp
  (paid licence) and Nessus (simulated). Every adapter emits the same
  `ScanVulnerability`, deduplicated by CVE with severity normalised from CVSS.
- **Grounded RAG assistant** — hybrid retrieval (exact CVE-ID lookup + semantic
  search) over an enriched knowledge base. Answers cite `[Doc N]`, and the
  assistant declines rather than inventing when the corpus has no answer.
- **Live threat intelligence** — CISA KEV, FIRST EPSS, NVD 2.0 and OSV, so
  prioritisation follows what is actually being exploited, not just CVSS.
- **AI scan briefings** — any completed scan is explained in plain language:
  bottom line, what to fix first, everything else, caveats.
- **Sharded reading across four free providers** — Groq, Gemini, OpenRouter
  (free models only) and NVIDIA each read a *different* slice of the retrieved
  evidence in parallel, then one small call merges their extracts. Cuts the
  tokens billed to any single free tier and keeps each model's context small
  enough to attend to. Each provider rotates across its whole model catalogue.
- **Verified answers** — every CVE ID, CWE ID, CVSS score and `[Doc N]`
  citation is checked against the retrieved text before the answer is returned.
  Unsupported claims are stripped, or named in a visible caveat.
- **Fully local option** — Ollama with local embeddings; nothing leaves the
  machine. Used automatically when no cloud provider is reachable.
- **Simulated data is labelled** — findings from a scanner that could not run
  are flagged per finding in the API, the UI and the assistant's context.
- **Research controls** — per-provider toggles, live model selection, a RAG
  on/off switch for the no-retrieval baseline, and a sharding switch for
  comparing sharded reading against the broadcast ensemble.
- **Attack path modelling** — NetworkX graphs of potential lateral movement.
- **Scan export** — JSON or CSV.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, Tailwind CSS, Vite, Lucide Icons, Recharts |
| **Backend** | FastAPI, SQLAlchemy, Pydantic v2 |
| **Database** | SQLite (scan state), ChromaDB (vector search) |
| **Embeddings** | `all-MiniLM-L6-v2`, run locally |
| **Cloud AI (free)** | Groq, Google Gemini, OpenRouter (free models only), NVIDIA NIM |
| **Local AI** | Ollama (any installed instruct model) |
| **Threat intel** | CISA KEV, FIRST EPSS, NVD 2.0, OSV.dev — all free, no key |
| **Network scanners** | Nmap, Nuclei, OpenVAS (GMP) |
| **Web scanners** | OWASP ZAP, Nikto, testssl/sslyze, WhatWeb |
| **Supply chain** | Trivy, OSV-Scanner, Grype |
| **Security** | defusedxml, SSRF prevention, rate limiting, argv-only subprocess calls |
| **Graphing** | NetworkX |

## Prerequisites

Only Python and Node are required. Every scanner and every AI provider is
optional — the app starts without them and tells you what is missing.

1. **Python 3.10+** and **Node.js 18+**
2. **An AI provider** (any one is enough; all have a free tier):
   - [Groq](https://console.groq.com/keys) — fastest
   - [Google Gemini](https://aistudio.google.com/apikey)
   - [OpenRouter](https://openrouter.ai/keys) — free models only
   - [NVIDIA NIM](https://build.nvidia.com)
   - [Ollama](https://ollama.com/) — fully local, no key
3. **Scanners** (optional): [Nmap](https://nmap.org/),
   [Nuclei](https://github.com/projectdiscovery/nuclei/releases),
   [Nikto](https://github.com/sullo/nikto),
   [Trivy](https://aquasecurity.github.io/trivy),
   [OSV-Scanner](https://github.com/google/osv-scanner),
   [Grype](https://github.com/anchore/grype),
   [OWASP ZAP](https://www.zaproxy.org/),
   [sslyze](https://github.com/nabla-c0d3/sslyze)
4. **OpenVAS** (optional): needs a running GVM stack plus `pip install python-gvm`

Copy `backend/.env.example` to `backend/.env` and add at least one API key.

> A tool that is not installed reports that it did not run — it never
> fabricates findings. Nessus is simulated only, and Burp needs a paid licence;
> both are labelled as such in the UI.

## Quickstart

### Windows

1. Clone or extract the repository.
2. Double-click **`Run_VulnDetect.bat`**.
3. The script will:
   - Verify Python and Node.js are installed (aborts with instructions if missing)
   - Create a Python virtual environment and install dependencies
   - Install frontend NPM packages
   - Auto-pull the `qwen2.5-coder:7b` Ollama model (if Ollama is installed)
   - Launch backend on `http://localhost:8000`
   - Launch frontend on `http://localhost:5173`
   - Open the browser automatically

### Linux / macOS

```bash
chmod +x Run_VulnDetect.sh
./Run_VulnDetect.sh
```

The script performs the same steps as the Windows version, with support for GNOME Terminal, xterm, and macOS Terminal.

### Manual Setup

**1. Start the Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

**2. Start the Frontend (in a new terminal):**
```bash
cd frontend
npm install
npm run dev
```

**3. Seed Vulnerability Knowledge Base (One-time):**
```bash
cd scripts
python seed_cve_data.py
```

**4. Configure Scanner Paths (Optional):**
Edit `backend/.env` if your scanners aren't in system PATH:
```env
NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
NUCLEI_PATH=C:\tools\nuclei\nuclei.exe
BURP_PATH=/path/to/burp
ZAP_PATH=/path/to/zap.sh
```

## Tuning the RAG pipeline

Set in `backend/.env`. Defaults are sensible; these exist so the pipeline can be
ablated for measurement rather than only configured.

| Variable | Default | Effect |
|----------|---------|--------|
| `RAG_ENABLED` | `1` | `0` switches retrieval off entirely — the no-RAG baseline |
| `RAG_MAP_REDUCE` | `1` | `0` reverts to one full-context call, for comparing against sharded reading |
| `RAG_SHARD_CHARS` | `2500` | Target document characters per provider per call. Lower spreads load wider and shrinks each context; raises the number of calls |
| `RAG_MIN_DOCS_TO_SHARD` | `3` | Below this, one call is cheaper than map calls plus a reduce |
| `RAG_MAX_SHARDS` | `6` | Ceiling on map calls per question, so a large retrieval cannot fan out and trip the limits sharding exists to avoid |
| `RAG_MAP_TIMEOUT` | `90` | Wall-clock ceiling on the map phase. Keep below `LLM_TIMEOUT`: an unreachable provider blocks for its full HTTP read timeout without erroring, and waiting it out delays every other provider's answer for nothing |
| `RAG_VERIFY` | `1` | `0` disables post-hoc grounding verification |
| `RAG_VERIFY_REPAIR` | `1` | `0` keeps unsupported claims but still caveats them, instead of spending a call to strip them |
| `RAG_SCORE_THRESHOLD` | `0.25` | Similarity floor below which a document counts as noise, not context |
| `RAG_OVERFETCH` | `4` | Multiplier on top-k before per-CVE dedupe |
| `RAG_CONTEXT_BUDGET` | `6000` | Total characters of retrieved context per question |

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Per-scanner availability, licence status, install hints |
| GET | `/api/llm-status` | Which AI providers are usable and which is active |
| POST | `/api/scans` | Start a scan (`{target, scanners[]}`) |
| GET | `/api/scans/{id}` | Scan status and progress |
| GET | `/api/scans/{id}/results` | Findings, each flagged `simulated` or not |
| POST | `/api/scans/{id}/explain` | **AI briefing** for the scan (optional `?question=`) |
| GET | `/api/scans/{id}/attack-paths` | Attack path graph |
| GET | `/api/scans/{id}/export?format=json\|csv` | Export findings |
| DELETE | `/api/scans/{id}` | Delete a scan |
| POST | `/api/rag/chat` | Chat with the RAG assistant |
| GET | `/api/rag/history/{session}` | Chat history |
| GET | `/api/rag/sessions` | List chat sessions |
| POST | `/api/rag/index` | Re-index the CVE corpus |
| GET | `/api/cve/{cve_id}` | CVE details |
| GET | `/api/cve?q=...&severity=...` | Search the CVE database |
| GET | `/api/providers` | **List AI providers with enabled state** |
| POST | `/api/providers/{provider}?enabled=` | **Enable or disable a provider** |
| GET | `/api/providers/{provider}/models` | **List a provider's live model catalogue** |
| POST | `/api/providers/{provider}/model?model=` | **Pin a model** |
| GET | `/api/rag-config` | **Retrieval state and corpus size** |
| POST | `/api/rag-config?enabled=` | **Turn retrieval on or off** |
| GET | `/api/eval-metrics` | **Latest evaluation results** |
| GET | `/api/logs` | Backend logs |

Full API docs at `http://localhost:8000/docs` when running.

## Evaluation Results

Two evaluations are reported. The **pilot** below ran 21 questions against a
50-CVE corpus and is what the earlier versions of this README quoted. The
**200-CVE run** further down is larger by an order of magnitude and corrects
two figures the pilot got optimistically wrong; read it as the current
measurement and the pilot as history.

### Pilot: 50 CVEs, 21 questions

Produced by `python scripts/run_eval.py --ablation`, which runs the live
pipeline end to end. Configuration: Groq `openai/gpt-oss-120b`, embeddings
`all-MiniLM-L6-v2`, 180 indexed chunks from 50 CVEs, top-k 5, 16 answerable
questions and 5 control questions about CVEs deliberately absent from the corpus.

| Metric | Full RAG | No retrieval | Delta |
|--------|----------|--------------|-------|
| ROUGE (mean) | **0.3591** | 0.0612 | +0.2979 |
| BLEU (mean) | **0.1892** | 0.0042 | +0.1850 |
| CVE fidelity | **0.8125** | 0.0000 | +0.8125 |
| Citation rate | **1.0000** | 0.0000 | +1.0000 |
| Fabricated CVE IDs | **3** | 16 | −13 |
| Correct refusals (of 5) | **3** | 0 | +3 |
| Mean generation latency | 13.5 s | 49.8 s | — |

*CVE fidelity* is the share of answers in which every CVE identifier mentioned
appears in the retrieved context; an identifier that does not was invented.

**Read these honestly.** Reference texts are drawn from the corpus itself, so
BLEU and ROUGE measure overlap with source material rather than correctness.
Retrieval scores hit@k = 1.0 here, but that is an artefact of construction and
of corpus size — identifier-style questions are resolved by exact lookup and
description-style questions reuse the indexed wording — so it is **not**
evidence of retrieval quality. The 200-CVE run below measures 0.885 on the
description-style half and supersedes this figure. The system still answered 2 of 5 questions about absent CVEs instead
of declining, so hallucination is reduced, not eliminated. An expert-graded
question set is needed before any claim of correctness.

Run your own: `python scripts/run_eval.py --ablation --limit 20`

#### Sharded reading vs. broadcast

Produced by `python scripts/run_eval.py --ablation --limit 8 --top-k 6`. The
`sharded` and `full` arms are a controlled pair: identical retrieval, identical
documents, identical questions, differing only in `RAG_MAP_REDUCE`.

| Metric | Sharded | Broadcast (`full`) | Change |
|--------|---------|--------------------|--------|
| **Peak tokens on one provider** | **1,562** | 8,310 | **5.3x lower** |
| **Mean generation latency** | **7.3 s** | 43.0 s | **5.9x faster** |
| Providers used per query | 2.86 | 1.00 | — |
| Fabricated CVE IDs | 0 | 0 | tied |
| CVE fidelity | 0.9375 | 0.9375 | tied |
| Correct refusals (of 5) | **5** | 4 | +1 |
| Grounding support rate | 0.9524 | 1.0000 | −0.05 |
| ROUGE (mean) | 0.2501 | 0.3001 | −0.05 |
| BLEU (mean) | 0.1062 | 0.1543 | −0.05 |

**What this does and does not show.**

The cost result is solid and reproducible: two independent runs measured 5.20x
and 5.32x lower peak per-provider load. That is the claim this design was built
to support, and the latency gap has the same cause — broadcast hits all four
providers with the full context at once, so they rate-limit together and the
rotator then walks entire model catalogues. One broadcast query took nine
minutes. No sharded query ever fell back.

**Sharding did not reduce hallucination.** Both arms fabricated zero CVE IDs on
answerable questions and scored identical CVE fidelity. Sharded refused one more
control question; broadcast scored one point higher on grounding support. These
differences are single-question artefacts on a 21-question set, not effects.
Retrieval had already taken fabrication to the floor, leaving no headroom for the
reading strategy to improve on — the hallucination result belongs to retrieval
and verification, not to sharding.

Sharded trails broadcast by about 0.05 on ROUGE and BLEU. Since references are
drawn from the corpus, that measures how much source wording survives, and the
map step's `NOTHING_RELEVANT` filter deliberately discards documents rather than
paraphrasing them, which lowers overlap. Treat it as a difference in verbosity,
not accuracy.

> **Threat to validity, stated up front:** each provider rotates across its model
> catalogue on rate limits, so the two arms are not guaranteed to be served by
> the same model. Answer-quality deltas between them are therefore **not** cleanly
> attributable to the reading strategy. Only the token distribution is a
> controlled measurement.

Two bugs found while running this comparison are worth recording, because both
made the system look worse than it was:

> **The verifier was checking nothing.** Several models format identifiers with
> non-breaking hyphens (`CVE‑2021‑44228`), which matched no pattern, so every
> answer was reported clean. `claims_checked: 0` was the only tell. Dash
> normalisation now runs before matching. A verification step that cannot fail
> loudly is worse than none.

> **The fabrication metric counted correct refusals.** Answering "CVE-2019-0708
> is not in the knowledge base" names the identifier, which scored as an
> invention — penalising exactly the behaviour the grounding rules exist to
> produce. Identifiers named in the question are now excluded from the check.

Running the baseline also surfaced a fault latent in the parallel orchestration
all along. NVIDIA's endpoint became unreachable and blocked for its full
180-second read timeout **without ever raising**; `as_completed(timeout=…)` then
raised out of the collection loop and the executor's context manager blocked on
shutdown waiting for that same stuck thread. One slow provider discarded the
answers of three that had already responded and dropped the query to local
Ollama. Both the ensemble and the map phase now catch that timeout and proceed
with whatever arrived, and the map phase is capped below the HTTP read timeout.
A baseline that silently degrades to a different model produces invalid
comparison data, which is why this was fixed before measuring anything.

### 200-CVE run — larger corpus, and what it changed

The pilot's corpus held 50 CVEs skewed hard toward CRITICAL and HIGH, and 21
questions. That is small enough that two of its headline numbers were artefacts
of the corpus rather than properties of the system. This run rebuilds the corpus
at 200 CVEs, balanced 50 per CVSS v3 severity band, and asks 405 questions.

```bash
python scripts/build_corpus_200.py      # 200 CVEs from NVD 2.0, balanced
python scripts/prewarm_enrichment.py    # warm the rate-limited NVD cache
python scripts/run_eval_200.py --condition retrieval   # no API key needed
python scripts/run_eval_200.py --condition sharded
```

The corpus and its vector store are separate files (`sample_nvd_200.json`,
collection `cve_knowledge_200`), so the pilot's corpus and results stay exactly
as they were and both runs remain reproducible.

| Property | Value |
|---|---|
| Severity bands | 50 CRITICAL / 50 HIGH / 50 MEDIUM / 50 LOW |
| Publication years | 148 from 2026, 11 from 2025, 41 from 2017–2024 |
| Indexed chunks | 510 |
| Questions | 400 answerable (200 CVEs x 2 phrasings) + 5 refusal controls |
| Overlap with the pilot corpus | 0 |

#### Retrieval is not perfect, and the pilot said it was

| Metric | Pilot (50 CVEs) | 200 CVEs |
|---|---|---|
| hit@k | 1.0000 | 0.9875 |
| P@1 — all questions | 1.0000 | 0.9425 |
| **P@1 — description-style only** | **1.0000** | **0.8850** |
| MRR | 1.0000 | 0.9631 |

Identifier-style questions still resolve perfectly, because an exact CVE ID is a
lookup rather than a semantic match. The description-style half is the honest
number, and at 200 CVEs it drops to 0.885. **The pilot's perfect retrieval was a
small-corpus artefact**: with 50 records there are too few near-neighbours for a
wrong one to win. Anyone quoting hit@k = 1.0 from the older tables should stop.

#### Sharded reading at scale

Both runs, sharded arm, 6 documents per query:

| Metric | Pilot (n=21) | 200 CVEs (n=405) |
|---|---|---|
| Queries split across providers | 21/21 | **405/405** |
| Mean shards per query | 2.86 | 2.98 |
| Fell back to single-provider | 0 | **0** |
| Peak tokens on one provider | 1,562 | **1,148** |
| Providers used per query | 2.86 | 2.96 |
| Grounding support rate | 0.9524 | **0.9722** |
| CVE fidelity | 0.9375 | 0.9325 |
| Correct refusals (of 5) | 5 | **5** |
| Fabricated CVE IDs | 0 | 7 (of 400 answers) |
| Citation rate | 0.7500 | 0.2675 |

What holds up: sharding itself. Every one of 405 queries split across three
distinct providers, and not one fell back to single-provider reading. Peak load
charged to any single endpoint fell to 1,148 tokens — 27% below the pilot — which
is the property this design exists to produce. Grounding support went up, and
refusal on the five absent-CVE controls stayed perfect with zero hallucinated
answers.

What does not: the **citation rate collapsed from 0.75 to 0.27**. The likely
cause is mechanical rather than a regression in answer quality — the share of
shards returning usable content fell from 0.71 to 0.39, so most shards now
correctly report `NOTHING_RELEVANT` and the surviving answer is built from a
single extract with fewer `[Doc N]` anchors to attach. That explanation is
untested. It is recorded here as an open question, not a finding.

Seven fabricated CVE identifiers appeared across 400 answers where the pilot had
none. On 21 questions, zero was never strong evidence of zero.

> **The `full` (broadcast) and `no_rag` arms at 200 CVEs are still running.**
> This section will gain their numbers when they land. Until then the
> broadcast comparison above is the pilot's, at n=21.

#### A measurement caveat found while running this

`EnsembleLLMClient` caps the broadcast path at a fixed 120-second wall clock and
proceeds with whichever providers finished. When a provider stalls, the recorded
`generation_ms` is that ceiling — a censored lower bound, not a measurement. Six
of the first questions in the 200-CVE broadcast arm hit it exactly. The warning
this logs is invisible under `run_eval.py`'s `logging.ERROR` level, so the only
tell is a suspiciously tight cluster at 122 s. Broadcast latency from that arm
will be reported as a median with the censoring stated, not as a bare mean.

#### ROUGE is not comparable between the two runs

NVD publishes no remediation prose. Where a reference carries NVD's own `Patch`
or `Vendor Advisory` tag the corpus builder points the `solution` field at it;
the rest get a generic line. Nothing is invented, but `run_eval.py` builds its
ROUGE reference as `description + " Remediation: " + solution`, so references in
the 200-CVE corpus are description-dominated and thinner than the hand-written
remediation text in the original 50. **Do not read the two ROUGE columns side by
side.** Grounding support, CVE fidelity, citation rate and every efficiency
measure are unaffected, and grounding support is the primary metric regardless.

## License

MIT License - see [LICENSE](LICENSE) for details.
