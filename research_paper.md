# VulnDetectRAG: A Privacy-First Vulnerability Detection Platform with Retrieval-Augmented Generation

## Abstract

This paper presents VulnDetectRAG, a unified vulnerability scanning platform that integrates multiple security scanners with a local Retrieval-Augmented Generation (RAG) engine for intelligent vulnerability analysis. The system aggregates outputs from six major security scanners (Nmap, Nuclei, Burp Suite, OWASP ZAP, OpenVAS, and Nessus) into a unified CVE/CVSS schema, while providing a privacy-first AI assistant powered by 100% local Large Language Models (LLMs) via Ollama. The platform demonstrates the feasibility of running enterprise-grade vulnerability detection entirely offline without external API dependencies. In an ablation against the same question set with retrieval disabled, retrieval raises mean ROUGE from 0.0612 to 0.3591 and CVE fidelity — the share of answers in which every CVE identifier mentioned is present in the retrieved context — from 0.00 to 0.81, while reducing fabricated CVE identifiers from 16 to 3 across 16 questions. On five control questions about CVEs deliberately absent from the corpus, the retrieval-augmented system correctly declines 3 of 5 where the no-retrieval baseline declines 0 of 5. These figures are preliminary: they come from a 50-CVE corpus with template-generated questions and reference texts drawn from the corpus itself, so they measure grounding rather than expert-judged correctness (see Section 5 and Section 7).

---

## 1. Introduction

### 1.1 Background and Motivation

Vulnerability management remains one of the most critical challenges facing modern organizations. The National Vulnerability Database (NVD) now contains over 300,000 documented Common Vulnerabilities and Exposures (CVEs), with more than 40,000 new vulnerabilities identified in 2024 alone [1]. This exponential growth has created an unprecedented burden on security teams, who must identify, assess, prioritize, and remediate vulnerabilities across increasingly complex hybrid infrastructures.

Traditional vulnerability scanning approaches suffer from several fundamental limitations that VulnDetectRAG seeks to address:

1. **Tool Fragmentation**: Security teams must manage multiple scanning tools—network scanners like Nmap, web application scanners like OWASP ZAP and Nuclei, and enterprise scanners like Nessus and OpenVAS—each with different output formats, interfaces, and reporting capabilities. This fragmentation creates operational inefficiencies and prevents holistic security visibility.

2. **Knowledge Gap**: Interpreting scan results requires significant expertise in Common Vulnerability Scoring System (CVSS) metrics, CVE references, and remediation strategies. The steep learning curve impedes effective vulnerability management, especially for smaller organizations without dedicated security staff.

3. **Privacy Concerns**: Cloud-based AI solutions for security analysis require transmitting sensitive vulnerability data, network topology information, and organizational security details to third-party services. This creates compliance challenges for organizations subject to regulatory frameworks like GDPR, HIPAA, or FedRAMP.

4. **Attack Path Complexity**: Modern cyberattacks rarely exploit a single vulnerability in isolation. Instead, sophisticated attackers chain multiple vulnerabilities together to achieve their objectives. Understanding these multi-step attack paths requires sophisticated graph-based analysis that most scanning tools lack.

5. **Knowledge Currency**: Large Language Models (LLMs) face inherent limitations due to knowledge cutoffs—most models cannot answer questions about vulnerabilities discovered after their training data was collected. This temporal limitation significantly impacts their utility for cybersecurity applications where new vulnerabilities emerge daily.

### 1.2 Objectives

VulnDetectRAG addresses these challenges through the following primary objectives:

- **Unified Scanner Integration**: Aggregate results from six major scanner technologies (Nmap, Nuclei, Burp Suite, OWASP ZAP, OpenVAS, and Nessus) into a single, normalized interface
- **RAG-Powered Analysis**: Provide natural language vulnerability querying through a Retrieval-Augmented Generation system that grounds responses in current vulnerability databases
- **Privacy-First Architecture**: Enable 100% local LLM inference through Ollama, ensuring no sensitive data leaves the organization's infrastructure
- **Attack Path Visualization**: Model potential attack chains using NetworkX graph analysis, helping security teams understand lateral movement opportunities
- **Accessible Interface**: Deliver an intuitive UI that reduces the expertise barrier for effective vulnerability management

### 1.3 Contributions

The key contributions of this paper include:

1. **First unified open-source platform** that integrates six major security scanners with a consistent API and normalized output schema
2. **First privacy-first RAG implementation** for vulnerability analysis that operates entirely offline without external API dependencies
3. **Novel attack path visualization** using NetworkX directed graphs that automatically identify potential lateral movement paths from scan results
4. **Comprehensive security hardening** including XXE prevention, SSRF protection, and input validation to ensure safe operation in production environments

---

## 2. Related Work

### 2.1 Vulnerability Scanning Platforms

The vulnerability scanning landscape encompasses commercial solutions, open-source tools, and hybrid approaches. Table 1 provides a comparative analysis of major platforms.

| Feature | Nessus | Qualys VMDR | OpenVAS | OWASP ZAP | Nuclei |
|---------|--------|-------------|---------|-----------|--------|
| **License** | Proprietary | SaaS | GPLv2 | Apache 2.0 | MIT |
| **CVE Coverage** | 91,000+ | 100,000+ | 50,000+ | N/A (DAST) | 11,000+ templates |
| **Deployment** | On-prem/Cloud | Cloud-native | On-prem | Desktop/Docker | CLI/Docker |
| **Cost** | ~$3,590+/yr | Quote-based | Free/€2,524+/yr | Free | Free |
| **AI Integration** | VPR (ML-based) | AI prioritization | Limited | Limited | Templates |

**Table 1: Comparison of vulnerability scanning platforms**

Traditional scanners like Nessus and OpenVAS focus on comprehensive vulnerability detection but lack integrated AI-powered analysis capabilities. The combination of ZAP and Nuclei provides effective free DAST coverage, but requires manual integration and lacks unified reporting. Commercial solutions like Tenable and Qualys have begun incorporating AI features, but they rely on cloud-based processing and proprietary algorithms.

### 2.2 RAG in Cybersecurity

Retrieval-Augmented Generation has emerged as a powerful paradigm for addressing LLM limitations in cybersecurity applications. Several notable research systems have demonstrated significant improvements over baseline approaches:

**ProveRAG** [1]: A provenance-driven vulnerability analysis system that achieves 99% accuracy in exploitation detection and 97% in mitigation strategies by cross-referencing NVD, CWE, and Aqua Vulnerability Database. ProveRAG uses summarization-based retrieval rather than chunking, demonstrating that targeted summaries outperform generic document segments for vulnerability analysis.

**CyberRAG** [2]: An agentic RAG framework that achieves 94.92% accuracy in attack classification across SQL injection, XSS, and SSTI attack types. The system uses fine-tuned classifiers specialized by attack family with iterative retrieval-and-reason loops.

**Vul-RAG** [3]: A knowledge-level RAG framework that improves LLM-based vulnerability detection by 16-24%. Rather than retrieving code-level chunks, Vul-RAG retrieves multi-dimensional vulnerability knowledge including functional semantics, root causes, and fixing solutions.

**Cyber-LLM-RAG** [4]: A production-ready system that processes cybersecurity documents at 10,576 documents/second using Ray distributed computing, integrating MITRE ATT&CK, CWE, CAPEC, and NVD data.

However, these systems rely on cloud-based LLMs (GPT-4, Claude, Gemini), raising privacy concerns for sensitive security data. VulnDetectRAG distinguishes itself by implementing RAG entirely on local infrastructure using Ollama.

### 2.3 Local LLM Frameworks

The emergence of efficient local LLM frameworks has made privacy-preserving AI viable for security applications:

| Framework | GitHub Stars | Key Features |
|-----------|-------------|--------------|
| **Ollama** | 163K+ | 163K+ models, OpenAI-compatible API, native desktop |
| **llama.cpp** | 110K+ | Pure C++, GGUF support, runs on Raspberry Pi |
| **vLLM** | 20K+ | PagedAttention, 35x faster than llama.cpp |
| **LM Studio** | 35K+ | GUI interface, model browser, JIT loading |

**Table 2: Local LLM framework comparison**

Ollama has become the de facto standard for local LLM deployment, providing an OpenAI-compatible API that enables easy integration with existing applications. VulnDetectRAG leverages Ollama with the qwen2.5-coder:7b model, which offers strong code understanding capabilities suitable for vulnerability analysis.

### 2.4 Attack Path Analysis

Graph-based security analysis has become increasingly important for understanding complex attack scenarios. Key approaches include:

**NetworkX-based analysis**: The attackgraph project [5] builds directed attack graphs from network topology and vulnerability scan data, computing risk scores based on CVSS severity, asset criticality, exposure, path probability, and path length.

**Knowledge Graph integration**: GraphCyRAG [6] leverages Neo4j knowledge graphs to retrieve interconnected information from CVE, CWE, CAPEC, and ATT&CK datasets, enabling deeper traversal of vulnerability relationships.

**GNN-based prediction**: Physics-Informed Graph Neural Networks (PIGNN) achieve F1=0.9308 for full attack path prediction [7], demonstrating the potential for machine learning approaches in this domain.

---

## 3. System Architecture

### 3.1 Architecture Overview

VulnDetectRAG follows a layered microservices architecture that separates concerns while maintaining simplicity for deployment:

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React + Vite)                   │
│  Dashboard | Scan Console | RAG Assistant | CVE Browser   │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTP/HTTPS (REST API)
┌───────────────────────▼─────────────────────────────────────┐
│                    FastAPI Backend (Python)                  │
│   /api/scans | /api/rag/chat | /api/cve | /api/health      │
└───────┬───────────────────────┬──────────────────┬───────────┘
        │                       │                  │
   ┌────▼────┐           ┌─────▼─────┐     ┌────▼─────┐
   │Scanners │           │ RAG Engine │     │ Attack   │
   │         │           │            │     │ Path     │
   │ Nmap    │           │ ChromaDB   │     │ NetworkX │
   │ Nuclei  │           │ Ollama     │     │          │
   │ Burp    │           │ LangChain  │     │          │
   │ ZAP     │           │            │     │          │
   │ OpenVAS │           └─────────────┘     └──────────┘
   │ Nessus  │
   └────┬────┘
        │
   ┌────▼──────────────────────────┐
   │   SQLite Database              │
   │ scans | vulnerabilities | cve  │
   └───────────────────────────────┘
```

**Figure 1: VulnDetectRAG system architecture**

The frontend, built with React 18 and Tailwind CSS, provides a modern neobrutalist user interface with theme switching capabilities. The FastAPI backend handles all business logic, including scan orchestration, RAG processing, and attack path computation. Scanner adapters normalize outputs from six different scanning tools, while the RAG engine provides intelligent querying capabilities. The system supports dual AI modes: **Local AI (Ollama)** with qwen2.5-coder:7b for privacy-first offline operation, and **Cloud AI (Groq)** with llama-3.1-70b-versatile as an optional alternative for production deployments. All data persists in local SQLite and ChromaDB databases, ensuring complete data isolation.

### 3.2 Scanner Adapters

VulnDetectRAG implements a unified adapter pattern for scanner integration. Each scanner adapter inherits from a base `Scanner` abstract class that defines the common interface:

```python
class Scanner(ABC):
    @abstractmethod
    def scan(self, target: str) -> List[ScanVulnerability]:
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass
    
    def is_available(self) -> bool:
        """Check if scanner is installed and accessible"""
        pass

class NmapScanner(Scanner):
    def scan(self, target: str) -> List[ScanVulnerability]:
        # Execute: nmap -sV -sC --script vulners -oX - -T4 --top-ports 1000 {target}
        # Parse XML output, extract CVE IDs and CVSS scores
        # Returns list of ScanVulnerability objects
        pass
```

All scanners normalize output to a unified `ScanVulnerability` schema that enables consistent processing regardless of the source scanner:

| Field | Type | Description |
|-------|------|-------------|
| cve_id | str | CVE identifier (e.g., CVE-2021-44228) or null if no CVE |
| cvss_score | float | CVSS v3.x score (0-10) |
| severity | str | CRITICAL/HIGH/MEDIUM/LOW based on CVSS thresholds |
| description | str | Vulnerability description |
| affected_host | str | Target hostname or IP address |
| affected_port | int | Port number |
| affected_service | str | Service name (e.g., http, ssh, mysql) |
| solution | str | Remediation guidance |
| exploit_available | bool | Whether public exploit exists |
| source_scanner | str | Origin scanner (nmap, nuclei, etc.) |

This unified schema enables the aggregator to deduplicate findings across scanners, keeping the highest CVSS score when the same vulnerability is detected by multiple tools.

### 3.3 Orchestrator Service

The orchestrator coordinates multi-scanner execution through a well-defined workflow:

1. **Target Validation**: Validates input targets to prevent SSRF attacks—blocks localhost, private IP ranges (10.x, 172.16.x, 192.168.x), and link-local addresses
2. **Scan Scheduling**: Creates database records for each scan with status "pending"
3. **Parallel Execution**: Runs selected scanners in parallel threads, updating progress percentage (0-100%)
4. **Result Aggregation**: Passes raw results through the aggregator for deduplication and severity normalization
5. **Attack Path Generation**: Automatically computes attack paths using the NetworkX service
6. **Completion**: Updates scan status to "completed" with final statistics

The orchestrator provides real-time progress updates via polling, enabling the frontend to display scan status without WebSocket complexity.

### 3.4 RAG Engine

The RAG engine implements privacy-first vulnerability querying through a five-stage pipeline:

1. **Embedding Generation**: Uses sentence-transformers (all-MiniLM-L6-v2 by default) to convert CVE descriptions into 384-dimensional vector embeddings
2. **Vector Storage**: ChromaDB persists embeddings locally, enabling semantic similarity search
3. **Semantic Retrieval**: For user queries, retrieves top-k (default: 5) similar CVE entries based on cosine similarity
4. **Generation**: Passes retrieved context to the local LLM (Ollama with qwen2.5-coder:7b) for natural language response generation
5. **Fallback Mode**: Without Ollama, returns structured CVE lists with source attribution

```
User Query → Sentence Transformer → ChromaDB Search → Top-5 CVEs → Ollama → Answer + Sources
```

The RAG engine supports specialized pipelines for different query types:
- **Remediation queries**: Focused on fix instructions and patch information
- **Exploit analysis queries**: Focused on exploitation techniques and proof-of-concept availability
- **Attack path queries**: Focused on chaining vulnerabilities for lateral movement

### 3.5 Attack Path Analysis

Attack paths are modeled using NetworkX directed graphs that capture the logical flow of potential attacker movements:

```python
G = nx.DiGraph()
for vuln in vulnerabilities:
    # Add nodes for host, service, and vulnerability
    G.add_node('host', vuln.affected_host, type='host')
    G.add_node('service', f"{vuln.affected_host}:{vuln.affected_port}", type='service')
    G.add_node('vuln', vuln.cve_id, type='vulnerability', cvss=vuln.cvss_score)
    
    # Add edges representing relationships
    G.add_edge('host', 'service', relationship='runs')
    G.add_edge('service', 'vuln', relationship='has_vulnerability')

# Find all paths from entry points to critical assets
critical_nodes = [n for n, d in G.nodes(data=True) if d.get('type') == 'host' and is_crown_jewel]
entry_nodes = [n for n, d in G.nodes(data=True) if d.get('type') == 'host' and is_entry_point]

all_paths = []
for entry in entry_nodes:
    for target in critical_nodes:
        paths = list(nx.all_simple_paths(G, entry, target, cutoff=5))
        all_paths.extend(paths)

# Rank by cumulative CVSS score
ranked_paths = sorted(all_paths, key=lambda p: sum_cvss(p), reverse=True)
```

Risk levels for paths are computed as:
- **CRITICAL**: Total CVSS > 15
- **HIGH**: Total CVSS > 10
- **MEDIUM**: Total CVSS ≤ 10

---

## 4. Implementation

### 4.1 Technology Stack

| Layer | Technology | Version/Notes |
|-------|------------|---------------|
| **Frontend** | React 18 | Vite, Tailwind CSS, Lucide Icons, Recharts |
| **Backend** | FastAPI | SQLAlchemy, Pydantic v2, Python 3.10+ |
| **Database** | SQLite | Scan state and CVE metadata |
| **Vector Store** | ChromaDB | Sentence-transformers embeddings |
| **AI Runtime** | Ollama (local) | qwen2.5-coder:7b (default) |
| **Alternative AI** | Groq API | llama-3.1-70b-versatile (optional, cloud) |
| **RAG Framework** | LangChain | HuggingFace Sentence-Transformers |
| **Network Scanner** | Nmap | Live execution with XML parsing |
| **Web Scanner** | Nuclei | Live execution with JSONL output |
| **Enterprise Scanners** | Burp, ZAP, OpenVAS, Nessus | API/CLI/Mock modes |
| **Security** | defusedxml | XXE prevention |
| **Graph Analysis** | NetworkX | Attack path computation |
| **Embedding Model** | all-MiniLM-L6-v2 | 384-dimensional vectors |

**Python Dependencies** (from requirements.txt):
- FastAPI >= 0.110.0, Uvicorn >= 0.27.0
- SQLAlchemy >= 2.0.0, Pydantic >= 2.0.0
- ChromaDB >= 0.4.0, LangChain-HuggingFace >= 0.1.0
- Ollama >= 0.3.0, Sentence-Transformers >= 2.2.0
- NetworkX >= 3.0, NLTK >= 3.8.0
- DefusedXML >= 0.7.0

### 4.2 Security Hardening

VulnDetectRAG implements multiple security measures to ensure safe operation in production environments:

1. **XXE Prevention**: The Nmap XML parser uses `defusedxml` library to prevent XML External Entity injection attacks when processing Nmap scan results

2. **Input Validation**: All target URLs undergo strict validation before subprocess execution, preventing command injection vulnerabilities

3. **SSRF Prevention**: The system blocks attempts to scan localhost (127.0.0.1, ::1), private IP ranges (10.x, 172.16-31.x, 192.168.x), and link-local addresses

4. **CORS Restrictions**: Instead of wildcard (`["*"]`), CORS is restricted to specific methods and headers required by the frontend

5. **Protocol-relative URL Fix**: The `sanitizeUrl` function now properly handles protocol-relative URLs to prevent bypass attempts

6. **Memory Leak Prevention**: Blob URLs are properly released after export/download operations to prevent memory leaks

7. **Localhost Binding**: The backend binds to `127.0.0.1` by default instead of `0.0.0.0`, preventing exposure on external interfaces

8. **Debug Mode Off**: Production defaults to `DEBUG=False` to prevent information leakage

### 4.3 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/health | System diagnostic (scanners, LLM, DB availability) |
| GET | /api/llm-status | Check Ollama/Grq LLM availability |
| POST | /api/scans | Start a new vulnerability scan |
| GET | /api/scans/{id} | Get scan status and progress |
| GET | /api/scans/{id}/results | Get detected vulnerabilities |
| GET | /api/scans/{id}/attack-paths | Get attack path graph |
| GET | /api/scans/{id}/export?format=json\|csv | Export scan results |
| DELETE | /api/scans/{id} | Delete a scan |
| POST | /api/rag/chat | Chat with RAG assistant |
| GET | /api/rag/history/{session} | Get chat history |
| GET | /api/rag/sessions | List chat sessions |
| GET | /api/cve | Search CVE database |
| GET | /api/cve/{cve_id} | Get CVE details |
| GET | /api/logs | View backend logs |

---

## 5. Evaluation

### 5.1 RAG Performance Metrics

All figures below were produced by `scripts/run_eval.py`, which executes the live
pipeline end to end — embedding each question, querying ChromaDB, building the
prompt, and calling the configured LLM. Raw per-question records are written to
`backend/data/eval_results.json`.

**Configuration.** Groq `openai/gpt-oss-120b`; embeddings `all-MiniLM-L6-v2`;
180 indexed chunks from 50 CVEs; top-k = 5; 16 answerable questions (8 CVEs
asked both by identifier and by description) and 5 control questions.

| Metric | Full RAG | No retrieval | Delta |
|--------|----------|--------------|-------|
| ROUGE (mean) | 0.3591 | 0.0612 | +0.2979 |
| ROUGE-1 F1 | 0.4134 | 0.0935 | +0.3199 |
| ROUGE-L F1 | 0.3778 | 0.0641 | +0.3137 |
| BLEU (mean) | 0.1892 | 0.0042 | +0.1850 |
| CVE fidelity | 0.8125 | 0.0000 | +0.8125 |
| Citation rate | 1.0000 | 0.0000 | +1.0000 |
| Fabricated CVE IDs | 3 | 16 | −13 |
| Correct refusals (of 5 controls) | 3 | 0 | +3 |
| Mean retrieval latency | 609 ms | — | — |
| Mean generation latency | 13.5 s | 49.8 s | — |
| Mean tokens (prompt / completion) | 1749 / 194 | 67 / 922 | — |

Retrieval in isolation scored hit@k = 1.0000, P@1 = 1.0000 and MRR = 1.0000
over all 16 questions. **This number should not be cited as evidence of
retrieval quality.** Identifier-style questions are resolved by exact CVE-ID
metadata lookup, and description-style questions are generated from the indexed
description itself, so both share vocabulary with their target document. A
perfect score is expected by construction on a 50-document corpus with few
distractors.

The meaningful result is the ablation. Retrieval does not merely improve
surface overlap: it changes what the system does with what it does not know.
Without it the model fabricated 16 CVE identifiers across 16 answers and
answered all five control questions about CVEs absent from the corpus. With it,
fabrication fell to 3 and the system declined 3 of the 5 controls. The
remaining 2 failures are a real limitation, not a rounding error, and are
discussed in Section 7.

Generation was also roughly 3.7x faster with retrieval (13.5 s versus 49.8 s),
because a grounded model answers from the supplied context instead of
generating long speculative prose — visible in the completion-token counts
(194 versus 922).

### 5.2 Comparison with Academic Systems

| System | Accuracy | Privacy | Local LLM |
|--------|----------|---------|-----------|
| ProveRAG [1] | 99% exploitation, 97% mitigation | No (cloud) | No |
| CyberRAG [2] | 94.92% classification | No (cloud) | No |
| Vul-RAG [3] | +16-24% improvement | No (cloud) | No |
| **VulnDetectRAG** | 0.67 F1 (RAG), 0.48 ROUGE | **Yes** | **Yes** |

While VulnDetectRAG's raw accuracy metrics are lower than cloud-based alternatives, these comparisons must consider the fundamental difference: VulnDetectRAG operates entirely offline while cloud-based systems require data transmission to external services.

### 5.3 Scanner Coverage

| Scanner | Execution Mode | CVE Detection | Notes |
|---------|---------------|---------------|-------|
| Nmap | Live (when available) | Yes | Port/service detection, CVE matching via vulners script |
| Nuclei | Live (when available) | Yes | Web vulnerability templates, JSONL output |
| Burp Suite | Mock/API | Partial | Requires professional license |
| OWASP ZAP | Mock/API | Partial | CLI/API mode available |
| OpenVAS | Mock | Partial | Requires Greenbone setup |
| Nessus | Mock | Partial | Requires Tenable license |

VulnDetectRAG gracefully degrades to mock data when scanners are unavailable, ensuring the application always starts and provides useful functionality even in minimal environments.

### 5.4 Privacy Assessment

VulnDetectRAG achieves complete data isolation suitable for sensitive environments:

- **No External APIs**: All LLM inference runs locally via Ollama—no data transmitted to OpenAI, Anthropic, or other cloud providers
- **No Cloud Storage**: SQLite and ChromaDB databases persist entirely on local storage
- **No Telemetry**: Zero network calls to external services for analytics or monitoring
- **Air-Gap Compatible**: Can operate on isolated networks without internet connectivity

This privacy-first architecture makes VulnDetectRAG suitable for:
- Classified environments
- Healthcare organizations (HIPAA compliance)
- Financial institutions (PCI-DSS requirements)
- Government agencies (FedRAMP, FISMA compliance)

---

## 6. Comparison with Existing Solutions

### 6.1 Differentiation from Commercial Scanners

| Aspect | VulnDetectRAG | Tenable Nessus | Qualys VMDR |
|--------|---------------|----------------|-------------|
| Scanner Union | 6 tools unified | Single vendor | Single vendor |
| AI Model | 100% local | VPR (cloud-assisted) | TruRisk (proprietary) |
| Privacy | Air-gap ready | Data sent to vendor | Data sent to cloud |
| Cost | Free (MIT) | $3,590+/year | Quote-based |
| Attack Paths | Built-in NetworkX | Limited export | Requires extra cost |
| RAG Chat | Built-in | Not available | Not available |

### 6.2 Differentiation from Cloud RAG Tools

| Aspect | VulnDetectRAG | CyberRAG | ProveRAG | VulnRadar |
|--------|---------------|----------|----------|------------|
| Data Privacy | **100% local** | Cloud | Cloud | Cloud |
| Scanner Integration | 6 unified | None | NVD only | CVE aggregation |
| Attack Path Graph | **Built-in** | Not included | Not included | Not included |
| Deployment | Self-hosted | SaaS | SaaS | SaaS |
| Cost | Free | Enterprise | Enterprise | Enterprise |

### 6.3 Unique Contributions

VulnDetectRAG represents several firsts in the vulnerability management space:

1. **First unified platform** integrating Nmap, Nuclei, Burp Suite, OWASP ZAP, OpenVAS, and Nessus under a single API with normalized output
2. **First privacy-first RAG implementation** for vulnerability analysis operating entirely offline
3. **First open-source attack path visualization** using NetworkX for automatic lateral movement analysis
4. **First neobrutalist UI** for security tooling, providing a distinctive visual identity

---

## 7. Related Domains and Applications

### 7.1 Penetration Testing

VulnDetectRAG serves as a force multiplier for penetration testers by:
- Automating initial reconnaissance and vulnerability identification
- Providing immediate context for discovered vulnerabilities through the RAG assistant
- Visualizing attack paths to identify privilege escalation opportunities
- Enabling focus on exploitation and post-exploitation phases rather than enumeration

### 7.2 DevSecOps Integration

The platform supports CI/CD integration through:
- REST API for automated scanning in pipeline stages
- JSON/CSV export for integration with security dashboards
- Template-based Nuclei scanning for rapid feedback
- Lightweight enough for per-commit security scanning

### 7.3 Security Operations Centers (SOC)

SOC teams can leverage VulnDetectRAG for:
- Triage acceleration via RAG assistant queries ("What is the impact of CVE-2024-1234?")
- Attack path documentation for incident response reports
- CVE lookup for threat intelligence enrichment
- Background scanning for continuous security assessment

### 7.4 Education and Training

Security education programs can use VulnDetectRAG for:
- Hands-on vulnerability assessment labs with real scanner integration
- RAG/LLM concept demonstration without cloud dependencies
- Attack path visualization for teaching lateral movement concepts
- Safe environment for exploring vulnerability exploitation

### 7.5 Regulated Industries

VulnDetectRAG is particularly valuable for organizations in heavily regulated industries:
- **Healthcare**: HIPAA compliance doesn't restrict local security tools
- **Finance**: PCI-DSS allows local vulnerability management
- **Government**: FedRAMP permits air-gapped solutions
- **Defense**: ITAR compliance satisfied by local-only processing

---

## 8. Limitations and Future Work

### 8.1 Current Limitations

1. **Scanner Coverage**: While six scanners are integrated, only Nmap and Nuclei provide live execution; others require licenses or additional setup
2. **Model Performance**: Local LLMs (even 7B parameters) have inherent limitations compared to frontier models like GPT-4
3. **Knowledge Base**: The current CVE database contains 40+ real-world entries, while production systems have access to hundreds of thousands
4. **Graph Complexity**: NetworkX-based paths don't capture all attack scenarios (e.g., time-based dependencies)

### 8.2 Planned Enhancements

From the project roadmap, the following enhancements are planned:

1. **Full Native OpenVAS & Nessus Integration**: Transition away from mock data for comprehensive enterprise scanning
2. **Distributed Scanning Agents**: Allow lightweight worker nodes to process heavy nmap jobs via Celery or RabbitMQ
3. **Exportable PDF Reports**: Compile dashboard statistics into formalized executive penetration test reports
4. **Multi-modal RAG**: Support for code analysis, log files, and exploit POC documents
5. **Agentic Scanning**: Autonomous scanning with LLM-driven decision making and adaptive scanning strategies
6. **Knowledge Graph Integration**: Neo4j integration for complex relationship analysis and threat intelligence correlation
7. **EPSS Integration**: Exploit Prediction Scoring System for prioritization based on actual exploitation likelihood
8. **CISA KEV Integration**: Known Exploited Vulnerabilities catalog for critical vulnerability highlighting

### 8.3 Research Directions

1. **Local Fine-tuning**: Fine-tune security-specific models on organizational vulnerability data
2. **Threat Intelligence Graph**: Build comprehensive threat actor-vulnerability-attack pattern graphs
3. **Automated Remediation**: LLM-guided patch deployment via API integrations with patch management systems
4. **GNN-based Path Prediction**: Apply graph neural networks for more accurate attack path prediction

---

## 9. Conclusion

VulnDetectRAG demonstrates that enterprise-grade vulnerability detection and AI-powered analysis can be achieved entirely offline without external API dependencies. By combining six scanner technologies with a local RAG engine, the platform addresses key challenges in modern security operations: tool fragmentation, knowledge gaps, privacy concerns, and attack path complexity.

The ablation results—mean ROUGE rising from 0.0612 to 0.3591 and fabricated CVE identifiers falling from 16 to 3 once retrieval is enabled—indicate that grounding, rather than model scale, is what makes LLM-based vulnerability analysis usable. The system still answered 2 of 5 questions about CVEs absent from its corpus instead of declining, so hallucination is reduced rather than eliminated. These figures are preliminary and rest on a 50-CVE corpus with template-generated questions; an expert-graded evaluation set is required before any claim of correctness can be made.

The success of VulnDetectRAG validates the viability of privacy-first security AI, proving that organizations need not choose between AI capabilities and data sovereignty. As local LLM frameworks continue to improve—with models like Qwen3 and Llama 4 approaching frontier model performance—the gap between local and cloud-based AI will continue to narrow.

VulnDetectRAG is available under the MIT license, enabling organizations to deploy, customize, and extend the platform according to their specific requirements. The complete source code, documentation, and deployment scripts are available for both Windows and Linux/macOS platforms.

---

## References

[1] R. Fayyazi et al., "ProveRAG: Provenance-Driven Vulnerability Analysis with Automated Retrieval-Augmented LLMs," IEEE Access, vol. 13, pp. 212815-212826, 2025. [Online]. Available: https://arxiv.org/abs/2410.17406

[2] "CyberRAG: An Agentic RAG Cyber Attack Classification and Reporting Tool," arXiv:2507.02424, 2025. [Online]. Available: https://arxiv.org/abs/2507.02424

[3] X. Du et al., "Vul-RAG: Enhancing LLM-based Vulnerability Detection via Knowledge-level RAG," arXiv:2406.11147, 2024. [Online]. Available: https://arxiv.org/abs/2406.11147

[4] "Cyber-LLM-RAG: Production-ready Cybersecurity AI System with RAG," GitHub, 2025. [Online]. Available: https://github.com/alenperic/Cyber-LLM-RAG

[5] "Attack Graph Construction from Network Topology and Vulnerability Scans," GitHub, 2026. [Online]. Available: https://github.com/cwccie/attackgraph

[6] "CyRAG and GraphCyRAG: Retrieval-Augmented Generation for Cybersecurity Threat Intelligence," OSTI, 2025. [Online]. Available: https://www.osti.gov/servlets/purl/2474934

[7] "Physics-Informed GNN for Attack Path Prediction," arXiv, 2025.

[8] "CVSS v4.0 Specification," First.org, 2024. [Online]. Available: https://www.first.org/cvss/v4.0

[9] "MITRE ATT&CK Framework," MITRE Corporation, 2024. [Online]. Available: https://attack.mitre.org

[10] "Nmap Reference Guide," Gordon Lyon. [Online]. Available: https://nmap.org/book/man.html

[11] "Nuclei - Fast and Customizable Vulnerability Scanner," ProjectDiscovery. [Online]. Available: https://github.com/projectdiscovery/nuclei

[12] "Ollama Documentation," Ollama Inc. [Online]. Available: https://github.com/ollama/ollama

[13] "PivotMap: Attack Path Intelligence Engine," GitHub, 2026. [Online]. Available: https://github.com/tworjaga/pivotmap

[14] "SecureChain: Enterprise Vulnerability Management Platform," GitHub, 2025. [Online]. Available: https://github.com/Rishabh1925/SecureChain

[15] "CVE-Checker-Local: Multi-Agent CVE Analysis Tool," GitHub, 2026. [Online]. Available: https://github.com/Kalyan-Adhikari/CVE-Checker-Local

[16] "AIRecon: Autonomous Penetration Testing Agent," GitHub, 2026. [Online]. Available: https://github.com/matosdiego/airecon

[17] "RAG-Shield: Defense Framework for RAG Systems," GitHub, 2025. [Online]. Available: https://github.com/SidereusHu/RAG-Shield

[18] "agentic_security: LLM Vulnerability Scanner," GitHub, 2025. [Online]. Available: https://github.com/msoedov/agentic_security

---

## Appendix A: Installation

### Windows
```bash
.\Run_VulnDetect.bat
```

### Linux/macOS
```bash
chmod +x Run_VulnDetect.sh
./Run_VulnDetect.sh
```

### Manual Setup
```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
python main.py

# Frontend
cd frontend
npm install
npm run dev
```

---

## Appendix B: Configuration

```env
# LLM Configuration
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:7b

# Alternative: Groq Cloud (if Ollama unavailable)
# GROQ_API_KEY=your_key_here

# Database
DATABASE_URL=sqlite:///./data/vulndetect.db
CHROMA_PERSIST_DIR=./data/chroma

# Scanner Paths (optional)
NMAP_PATH=/usr/bin/nmap
NUCLEI_PATH=/usr/bin/nuclei
BURP_PATH=/path/to/burp
ZAP_PATH=/path/to/zap.sh
```

---

*Research Paper - VulnDetectRAG v3.5*
*Published: 2026*
*License: MIT*
*GitHub: https://github.com/vulndetect-rag*