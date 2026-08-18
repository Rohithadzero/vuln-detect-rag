# Centralized Vulnerability Detection & Intelligent Query (RAG)

![Version](https://img.shields.io/badge/version-v3.5-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Node](https://img.shields.io/badge/node-18.x-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macOS-lightgrey)

A unified vulnerability scanning platform with RAG-powered intelligence across Nmap, Nuclei, OpenVAS, Nessus, Burp Suite, and OWASP ZAP, featuring **local or cloud AI** via **Ollama** (local) or **Groq** (cloud API).

## Architecture

```text
Frontend (React + Neobrutalist UI)  →  FastAPI Backend  →  SQLite + ChromaDB
                                          ↓
                              Scanner Adapters (Nmap/Nuclei/Burp/ZAP/OpenVAS/Nessus)
                                          ↓
                              RAG Engine (LangChain + Ollama/Groq)
```

## What's New in v3.5

- **Neobrutalist UI Redesign**: Complete frontend overhaul with bold neobrutalist design system — black borders, offset shadows, uppercase typography. Includes a Classic/Color theme toggle with gradient glassmorphism mode.
- **Theme System**: Switch between Classic (clean neobrutalism) and Color (gradient glassmorphism) themes. Preference is persisted to localStorage.
- **6 Scanner Support**: Added Burp Suite and OWASP ZAP scanner adapters alongside Nmap, Nuclei, OpenVAS, and Nessus. Each scanner supports live execution with automatic mock fallback.
- **Security Hardening**:
  - Fixed XML External Entity (XXE) vulnerability in Nmap XML parser (`defusedxml`)
  - Fixed `/api/logs` endpoint reading wrong file path
  - Restricted CORS to specific methods and headers (was `["*"]`)
  - Added target input validation before subprocess execution
  - Fixed protocol-relative URL bypass in `sanitizeUrl`
  - Fixed memory leaks from unreleased Blob URLs in export/download
  - Bound backend to `127.0.0.1` instead of `0.0.0.0` by default
  - Set `DEBUG=False` by default
- **Bug Fixes**:
  - Fixed race condition in scan polling (duplicate `loadAttackPaths` calls)
  - Fixed null dereference crash when vulnerabilities array is empty
  - Fixed undefined CSS class `theme-color-surface` in Layout
  - Fixed theme value injection via localStorage validation
- **Launcher Script Fixes**:
  - `Run_VulnDetect.sh`: Fixed 5 unclosed echo strings (critical parse error), fixed double-cd path bug (`backend/backend`), added `SCRIPT_DIR` resolution for reliable paths, added prerequisite hard stops
  - `Run_VulnDetect.bat`: Added `%~dp0` for reliable path resolution, added prerequisite hard stops with helpful download links, added directory existence checks, added venv creation error handling
- **Cleaned Dependencies**: Removed 7 unused packages from `requirements.txt` (langchain base, langchain-core, langchain-ollama, langchain-community, rouge-score, pyyaml, pandas). Added `defusedxml` and `ollama`.

<details>
<summary>Previous Updates</summary>

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

- **100% Local AI** — Vulnerability analysis using offline LLMs via Ollama. No data leaves your machine.
- **6-Scanner Aggregation** — Normalize outputs from Nmap, Nuclei, Burp Suite, OWASP ZAP, OpenVAS, and Nessus into a unified CVE/CVSS schema.
- **Real Vulnerability Scanning** — Live nmap (`-sV -sC --script vulners`) and nuclei scans directly from the UI.
- **RAG Chat Assistant** — Ask about CVEs, remediation steps, and exploit techniques. Supports specialized pipelines (remediation, exploit analysis, attack path).
- **Attack Path Modeling** — Visualize potential attack chains using NetworkX graph analysis.
- **Neobrutalist UI** — Bold, distinctive interface with theme switching (Classic/Color modes).
- **CVE Database** — Browse and search 40+ real-world CVEs with severity filtering.
- **Scan Export** — Download scan results as JSON or CSV.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, Tailwind CSS, Vite, Lucide Icons, Recharts |
| **Backend** | FastAPI, SQLAlchemy, Pydantic v2 |
| **Database** | SQLite (Scan State), ChromaDB (Vector Search) |
| **AI** | Ollama (`qwen2.5-coder:7b`) or Groq (`llama-3.1-70b-versatile`), LangChain, HuggingFace Sentence-Transformers |
| **Scanners** | Nmap (Live), Nuclei (Live), Burp Suite (API/CLI/Mock), OWASP ZAP (API/CLI/Mock), OpenVAS (Mock), Nessus (Mock) |
| **Security** | defusedxml, SSRF prevention, rate limiting, input sanitization |
| **Graphing** | NetworkX (Attack Path Calculation) |

## Prerequisites

1. **Python 3.10+** (Added to system PATH)
2. **Node.js 18+** (Added to system PATH)
3. **Ollama** — Install from [ollama.com](https://ollama.com/) (Optional, for local AI)
4. **Groq API Key** — Get from [console.groq.com](https://console.groq.com/) (Optional, for cloud AI)
5. **Nmap** — [nmap.org](https://nmap.org/) (Optional, for live scanning)
6. **Nuclei** — [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei/releases) (Optional, for active scanning)

> *Note: If scanners or Ollama are missing, the platform falls back to mock data. The application always starts. Use Groq for production deployment without local AI setup.*

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
| GET | `/api/health` | System diagnostic (scanners, LLM, DB) |
| GET | `/api/llm-status` | Check Ollama LLM availability |
| POST | `/api/scans` | Start a new vulnerability scan |
| GET | `/api/scans/{id}` | Get scan status |
| GET | `/api/scans/{id}/results` | Get scan vulnerabilities |
| GET | `/api/scans/{id}/attack-paths` | Get attack path graph |
| GET | `/api/scans/{id}/export?format=json\|csv` | Export scan results |
| DELETE | `/api/scans/{id}` | Delete a scan |
| POST | `/api/rag/chat` | Chat with RAG assistant |
| GET | `/api/rag/history/{session}` | Get chat history |
| GET | `/api/rag/sessions` | List chat sessions |
| GET | `/api/cve/{cve_id}` | Get CVE details |
| GET | `/api/cve?q=...&severity=...` | Search CVE database |
| GET | `/api/logs` | View backend logs |

Full API docs available at `http://localhost:8000/docs` when running.

## Evaluation Results

| Metric | Score | Note |
|--------|-------|------|
| CVE Detection F1 | 0.6667 | Solid entity extraction accuracy |
| BLEU Score | 0.2102 | Contextual phrasing match |
| ROUGE Score | 0.4809 | Excellent topical capture |

Run your own evaluations: `cd scripts && python run_eval.py`

## License

MIT License - see [LICENSE](LICENSE) for details.
