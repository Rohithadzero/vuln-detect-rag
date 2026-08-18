import os
from pathlib import Path
from pydantic_settings import BaseSettings


# Get absolute paths based on project root
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
DATA_DIR = PROJECT_ROOT / "backend" / "data"


def _to_sqlite_path(path: Path) -> str:
    """Convert path to SQLite-compatible format (forward slashes)."""
    return str(path).replace("\\", "/")


def _parse_cors_origins(origins_str: str | None) -> list[str]:
    """Parse comma-separated CORS origins from environment variable."""
    default_origins = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]
    if not origins_str:
        return default_origins
    return [origin.strip() for origin in origins_str.split(",") if origin.strip()]


class Settings(BaseSettings):
    APP_NAME: str = "VulnDetectRAG"
    APP_VERSION: str = "3.5.0"
    DEBUG: bool = False

    # Database - use absolute path with forward slashes for SQLite
    DATABASE_URL: str = f"sqlite:///{_to_sqlite_path(DATA_DIR)}/vulndetect.db"

    # Vector DB
    CHROMA_PERSIST_DIR: str = str(DATA_DIR / "chroma")
    CHROMA_COLLECTION: str = "cve_knowledge"

    # LLM Provider (ollama or groq)
    LLM_PROVIDER: str = "ollama"

    # Ollama Local LLM
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:7b"

    # Groq API
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.1-70b-versatile"

    # Embedding (local)
    USE_LOCAL_EMBEDDINGS: bool = True
    LOCAL_EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

    # CORS - support environment override with comma-separated list
    # Set CORS_ORIGINS env var with comma-separated URLs
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]
    CORS_ORIGINS_ENV: str = ""  # Set via environment variable

    # Scanner paths - will be auto-detected if not set
    NMAP_PATH: str = ""
    NUCLEI_PATH: str = ""
    OPENVAS_PATH: str = ""
    NESSUS_PATH: str = ""
    BURP_PATH: str = ""  # Burp Suite
    ZAP_PATH: str = ""  # OWASP ZAP

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Parse CORS origins from environment if set
        env_origins = os.environ.get("CORS_ORIGINS", "")
        if env_origins:
            self.CORS_ORIGINS = _parse_cors_origins(env_origins)
        elif self.CORS_ORIGINS_ENV:
            self.CORS_ORIGINS = _parse_cors_origins(self.CORS_ORIGINS_ENV)


settings = Settings()


def ensure_dirs():
    """Create data directories. Called during app startup."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        import logging

        logging.warning(f"Cannot create data directory: {e}. Using fallback location.")
        Path("./data").mkdir(exist_ok=True)

    chroma_dir = Path(settings.CHROMA_PERSIST_DIR)
    try:
        chroma_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        import logging

        logging.warning(f"Cannot create chroma directory: {e}")
        # Fallback to default location
        settings.CHROMA_PERSIST_DIR = str(DATA_DIR / "chroma")
        (DATA_DIR / "chroma").mkdir(parents=True, exist_ok=True)
