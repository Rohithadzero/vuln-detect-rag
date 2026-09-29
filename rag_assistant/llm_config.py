"""Backward-compatible import path; the implementation lives in rag_assistant.llm."""

from .llm import *  # noqa: F401,F403
from .llm import (
    _THINK_BLOCK,
    _THINK_OPEN,
    _MODEL_CATALOGUE_CACHE,
    _CATALOGUE_TTL_SECONDS,
    _OLLAMA_STATUS_CACHE,
    _OLLAMA_UP_TTL_SECONDS,
    _OLLAMA_DOWN_TTL_SECONDS,
    _OLLAMA_CONNECT_TIMEOUT,
    _OLLAMA_READ_TIMEOUT,
    _cache_ollama_status,
    _build_rotating_client,
)
