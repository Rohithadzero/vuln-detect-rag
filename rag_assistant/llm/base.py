"""Shared types and base class for LLM clients."""

import re
import time
import logging
from typing import Optional, Dict, Any, List, Iterator, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)


#: Reasoning models wrap their chain-of-thought in <think>...</think> inside the
#: normal content field. Ollama's structured `thinking` field is handled
#: separately, but models served over the OpenAI-compatible APIs emit the tags
#: inline, and an unstripped block puts raw reasoning in front of the user and
#: drags every text-overlap metric down. Stripping is unconditional: the tags
#: are never wanted in an answer.
_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
#: An unclosed opener means the budget ran out mid-thought; everything after it
#: is reasoning, not answer.
_THINK_OPEN = re.compile(r"<think>.*$", re.DOTALL | re.IGNORECASE)


def strip_reasoning(text: str) -> str:
    """Remove inline chain-of-thought blocks from generated text."""
    if not text or '<think' not in text.lower():
        return text
    cleaned = _THINK_BLOCK.sub("", text)
    cleaned = _THINK_OPEN.sub("", cleaned)
    return cleaned.strip()


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    provider: str
    model: str
    temperature: float = 0.0
    max_tokens: int = 2000
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    #: Context window to request. Vulnerability prompts carry several retrieved
    #: documents plus history, and Ollama silently truncates to 2048 tokens by
    #: default, which drops the retrieved context before the model ever sees it.
    context_window: int = 8192
    request_timeout: int = 180
    max_retries: int = 2


@dataclass
class LLMResult:
    """A completion plus the telemetry needed to evaluate it."""
    text: str
    model: str
    provider: str
    latency_ms: float = 0.0
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


class LLMUnavailableError(RuntimeError):
    """Raised when the configured LLM backend cannot be reached."""


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""

    #: Whether this backend can execute tool/function calls.
    supports_tools: bool = False

    def __init__(self, config: LLMConfig):
        """Initialize LLM client.

        Args:
            config: LLM configuration
        """
        self.config = config

    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate text from prompt.

        Args:
            prompt: Input prompt
            **kwargs: Additional generation parameters

        Returns:
            Generated text
        """

    @abstractmethod
    def get_embedding(self, text: str) -> list:
        """Get embedding for text.

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """

    def generate_detailed(self, prompt: str, system: Optional[str] = None,
                          **kwargs) -> LLMResult:
        """Generate and return telemetry alongside the text.

        Default implementation wraps ``generate`` and times it; backends that
        expose token counts override this.
        """
        started = time.perf_counter()
        try:
            text = self.generate(prompt, system=system, **kwargs)
            return LLMResult(
                text=strip_reasoning(text),
                model=self.config.model,
                provider=self.config.provider,
                latency_ms=round((time.perf_counter() - started) * 1000, 1),
            )
        except Exception as e:
            return LLMResult(
                text="",
                model=self.config.model,
                provider=self.config.provider,
                latency_ms=round((time.perf_counter() - started) * 1000, 1),
                error=str(e),
            )

    def stream(self, prompt: str, system: Optional[str] = None,
               **kwargs) -> Iterator[str]:
        """Yield the completion incrementally.

        Backends without native streaming yield the whole answer once.
        """
        yield self.generate(prompt, system=system, **kwargs)

    def chat_with_tools(self, messages: List[Dict[str, Any]],
                        tools: List[Dict[str, Any]], **kwargs) -> LLMResult:
        """Run one tool-calling turn. Only supported by some backends."""
        raise NotImplementedError(
            f"{self.config.provider} client does not support tool calling"
        )

    def _retry(self, fn: Callable[[], Any], label: str) -> Any:
        """Run ``fn`` with bounded retries and exponential backoff."""
        last_error: Optional[Exception] = None
        for attempt in range(self.config.max_retries + 1):
            try:
                return fn()
            except Exception as e:
                last_error = e
                if attempt < self.config.max_retries:
                    delay = 2 ** attempt
                    logger.warning("%s failed (attempt %d/%d): %s — retrying in %ds",
                                   label, attempt + 1, self.config.max_retries + 1,
                                   e, delay)
                    time.sleep(delay)
        raise last_error  # type: ignore[misc]
