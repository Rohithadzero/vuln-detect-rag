# archive/ — non-canonical variants, reference only

`EMET/` and `v1.5/` are quarantined duplicate copies of this project. **They are not the system described by `README.md` or `research_paper.md`, they are not built, tested, or run, and no paper claim, benchmark, or demo script may reference them.** The canonical tree is the repo root (`backend/`, `frontend/`, `rag_assistant/`, `scripts/`).

| Directory | What it is | Why it must not be cited |
|---|---|---|
| `EMET/` | A Netlify-targeted frontend build (snapshot 2026-03-28) | Has **no functional Python backend path in use**: it scans via `frontend/src/services/mockScanner.js`, a hardcoded JS array, and answers chat by calling `api.groq.com` directly from the browser (`frontend/src/api/groqClient.js`). No local LLM, no vector store, no real scanning. Contradicts the privacy-first claim. |
| `v1.5/` | An older full snapshot (2026-03-28) | Superseded; retained only for diffing against the canonical tree. |

Both trees are `.gitignore`d (this README is tracked). They remain on disk for reference; nothing imports from them.

See `../AUDIT_REPORT.md` for the full analysis that motivated this quarantine.
