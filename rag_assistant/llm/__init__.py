"""LLM providers, factory and composite clients."""

from .base import (
    _THINK_BLOCK,
    _THINK_OPEN,
    strip_reasoning,
    LLMConfig,
    LLMResult,
    LLMUnavailableError,
    BaseLLMClient,
)
from .openai_client import (
    OpenAIClient,
)
from .ollama_client import (
    OllamaClient,
)
from .remote_clients import (
    RemoteModelResolverMixin,
    GeminiClient,
    GroqClient,
    OpenRouterClient,
    NvidiaClient,
    HuggingFaceClient,
)
from .factory import (
    LLMFactory,
    _MODEL_CATALOGUE_CACHE,
    _CATALOGUE_TTL_SECONDS,
    _OLLAMA_STATUS_CACHE,
    _OLLAMA_UP_TTL_SECONDS,
    _OLLAMA_DOWN_TTL_SECONDS,
    _OLLAMA_CONNECT_TIMEOUT,
    _OLLAMA_READ_TIMEOUT,
    _cache_ollama_status,
)
from .composite import (
    ModelRotatingClient,
    EnsembleLLMClient,
    FallbackLLMClient,
    CLOUD_PROVIDERS,
    _build_rotating_client,
    get_cloud_clients,
    get_local_clients,
    get_llm_client,
)
