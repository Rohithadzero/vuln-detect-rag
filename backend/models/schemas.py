from datetime import datetime
from pydantic import BaseModel, Field, model_validator, ConfigDict
from typing import Literal, Optional


# --- Vulnerability Schemas ---


class VulnerabilityBase(BaseModel):
    cve_id: Optional[str] = None
    cvss_score: float = 0.0
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "LOW"
    description: str = ""
    affected_host: str = ""
    affected_port: Optional[int] = None
    affected_service: Optional[str] = None
    solution: str = ""
    references: list[str] = Field(default_factory=list)
    exploit_available: bool = False
    source_scanner: str = ""
    raw_output: dict = Field(default_factory=dict)


class VulnerabilityCreate(VulnerabilityBase):
    scan_id: int


class VulnerabilityResponse(VulnerabilityBase):
    id: int
    scan_id: int
    created_at: datetime
    #: True when this finding is simulated sample data produced because the
    #: scanner was unavailable, rather than something observed on the target.
    #: Derived from raw_output so the UI can mark it per finding instead of
    #: only per scanner selection.
    simulated: bool = False

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="after")
    def _flag_simulated(self):
        """Surface the mock marker that scanner adapters already record."""
        raw = self.raw_output or {}
        object.__setattr__(self, "simulated", raw.get("type") == "mock")
        return self


# --- Scan Schemas ---


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP to scan")
    scanners: list[str] = Field(
        default=["nmap", "nuclei"], description="List of scanners to use"
    )


class ScanResponse(BaseModel):
    id: int
    target: str
    status: str
    scanners_used: list[str]
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    avg_cvss: float
    progress: int = 0
    current_scanner: str = ""
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    #: Estimated running time for the scan's background work. Derived from the
    #: selected scanners and elapsed time so the client can show a wait, and an
    #: honest "more time needed" once the scan runs past its estimate.
    eta_seconds: int = 0
    eta_remaining_seconds: int = 0
    overrun: bool = False
    eta_message: str = ""

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="after")
    def _fill_eta(self):
        """Compute the ETA fields from the scan's status and timing."""
        from services.eta import compute_eta

        eta = compute_eta(
            self.status, self.scanners_used, self.started_at, self.completed_at
        )
        for key, value in eta.items():
            object.__setattr__(self, key, value)
        return self


class ScanResultsResponse(BaseModel):
    scan: ScanResponse
    vulnerabilities: list[VulnerabilityResponse]


# --- CVE Schemas ---


class CVEResponse(BaseModel):
    id: int
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    solution: str
    references: list[str]
    exploit_available: bool
    source: str
    indexed_at: datetime

    model_config = ConfigDict(from_attributes=True)


# --- RAG Schemas ---


class ChatRequest(BaseModel):
    message: str = Field(
        ..., description="User question about vulnerabilities", max_length=10000
    )
    session_id: str = Field(
        default="default", description="Chat session ID", max_length=200
    )


class ChatSource(BaseModel):
    cve_id: Optional[str] = None
    content: str = ""
    score: float = 0.0


class ChatResponse(BaseModel):
    answer: str
    sources: list[ChatSource] = Field(default_factory=list)
    session_id: str


class ChatMessageResponse(BaseModel):
    id: int
    session_id: str
    role: str
    content: str
    sources: list[dict] = Field(default_factory=list)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# --- Attack Path Schemas ---


class AttackNode(BaseModel):
    id: str
    label: str
    type: str  # host, vulnerability, service
    severity: Optional[str] = None
    cvss_score: Optional[float] = None


class AttackEdge(BaseModel):
    source: str
    target: str
    label: Optional[str] = None


class AttackPath(BaseModel):
    path_id: str
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    total_cvss: float
    risk_level: str


class AttackPathsResponse(BaseModel):
    scan_id: int
    paths: list[AttackPath]
    total_paths: int


# --- Stats Schemas ---


class DashboardStats(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    critical_vulns: int
    high_vulns: int
    medium_vulns: int
    low_vulns: int
    avg_cvss: float
    recent_scans: list[ScanResponse]


# --- Sanitizer Schemas ---


class SanitizeIndicator(BaseModel):
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    title: str
    detail: str = ""


class SanitizeItemResult(BaseModel):
    kind: Literal["file", "link"]
    name: str
    verdict: Literal["clean", "low", "suspicious", "malicious", "error"]
    score: int = 0
    sha256: Optional[str] = None
    size: Optional[int] = None
    detected_type: Optional[str] = None
    sanitized: Optional[str] = None
    note: str = ""
    indicators: list[SanitizeIndicator] = Field(default_factory=list)
    engines: dict = Field(default_factory=dict)


class SanitizeResponse(BaseModel):
    results: list[SanitizeItemResult]


class LinkSanitizeRequest(BaseModel):
    urls: list[str] = Field(..., max_length=50, description="URLs to screen")


# --- Evaluation Schemas ---


class EvalResult(BaseModel):
    metric: str
    score: float
    details: dict = Field(default_factory=dict)
