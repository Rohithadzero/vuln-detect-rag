# Centralized Vulnerability Detection & Intelligent Query (RAG)

![Version](https://img.shields.io/badge/version-v4.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Node](https://img.shields.io/badge/node-18.x-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macOS-lightgrey)

A unified vulnerability scanning platform with RAG-powered intelligence across **twelve security tools** — network, web and supply chain — with answers grounded in a live-enriched CVE knowledge base.

The AI layer orchestrates **four free cloud providers** (Groq, Google Gemini, OpenRouter, NVIDIA NIM) in parallel and reconciles their answers, falling back to a **fully local Ollama** model when every cloud provider is unreachable.

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
  ┌───────────────────────────────────────────────────────────┐
  │  Groq ──┐                                                  │
  │  Gemini ├─ queried in parallel, answers reconciled         │
  │  OpenRouter (free models only)                             │
  │  NVIDIA ─┘   each rotates across its whole model catalogue │
  │                                                            │
  │  Ollama (local) — only when every cloud provider fails     │
  └───────────────────────────────────────────────────────────┘
              │
              ▼
  Plain-language briefing, with [Doc N] citations
```

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

### Multi-provider AI orchestration

Four free cloud providers queried **in parallel** and reconciled into one
answer, each **rotating across its entire model catalogue** so a rate-limited
or retired model degrades the answer instead of breaking it. Ollama is the
offline last resort. Cloud-tagged Ollama models are never auto-selected, since
they would send scan data off-machine.

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
- **Four free cloud providers, orchestrated** — Groq, Gemini, OpenRouter
  (free models only) and NVIDIA queried in parallel and reconciled, each
  rotating across its whole model catalogue.
- **Fully local option** — Ollama with local embeddings; nothing leaves the
  machine. Used automatically when no cloud provider is reachable.
- **Simulated data is labelled** — findings from a scanner that could not run
  are flagged per finding in the API, the UI and the assistant's context.
- **Research controls** — per-provider toggles, live model selection, and a RAG
  on/off switch for measuring the no-retrieval baseline.
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
Retrieval scores hit@k = 1.0, but that is an artefact of construction —
identifier-style questions are resolved by exact lookup and description-style
questions reuse the indexed wording — so it is **not** evidence of retrieval
quality. The system still answered 2 of 5 questions about absent CVEs instead
of declining, so hallucination is reduced, not eliminated. An expert-graded
question set is needed before any claim of correctness.

Run your own: `python scripts/run_eval.py --ablation --limit 20`

## License

MIT License - see [LICENSE](LICENSE) for details.
