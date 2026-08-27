"""LLM configuration and factory for multiple providers."""

import os
import re
import time
import logging
from typing import Optional, Dict, Any, Union, List, Iterator, Callable, Tuple
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

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
        pass

    @abstractmethod
    def get_embedding(self, text: str) -> list:
        """Get embedding for text.

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        pass

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


class OpenAIClient(BaseLLMClient):
    """OpenAI GPT client."""

    supports_tools = True

    def __init__(self, config: LLMConfig):
        """Initialize OpenAI client."""
        super().__init__(config)
        self._client = None

    @property
    def client(self):
        """Get or create OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=self.config.api_key,
                    timeout=self.config.request_timeout,
                )
            except ImportError:
                logger.error(
                    "OpenAI package not installed. Install it with: pip install openai"
                )
                raise
        return self._client

    def _messages(self, prompt: str, system: Optional[str]) -> List[Dict[str, str]]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return messages

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """Generate text using OpenAI."""
        return self.generate_detailed(prompt, system=system, **kwargs).text

    def generate_detailed(self, prompt: str, system: Optional[str] = None,
                          **kwargs) -> LLMResult:
        started = time.perf_counter()
        try:
            response = self._retry(
                lambda: self.client.chat.completions.create(
                    model=self.config.model,
                    messages=self._messages(prompt, system),
                    temperature=kwargs.get('temperature', self.config.temperature),
                    max_tokens=kwargs.get('max_tokens', self.config.max_tokens),
                ),
                "OpenAI generation",
            )
            usage = getattr(response, 'usage', None)
            return LLMResult(
                text=response.choices[0].message.content or "",
                model=self.config.model,
                provider=self.config.provider,
                latency_ms=round((time.perf_counter() - started) * 1000, 1),
                prompt_tokens=getattr(usage, 'prompt_tokens', None),
                completion_tokens=getattr(usage, 'completion_tokens', None),
            )
        except Exception as e:
            logger.error(f"OpenAI generation error: {e}")
            raise

    def stream(self, prompt: str, system: Optional[str] = None, **kwargs) -> Iterator[str]:
        """Stream tokens from OpenAI."""
        stream = self.client.chat.completions.create(
            model=self.config.model,
            messages=self._messages(prompt, system),
            temperature=kwargs.get('temperature', self.config.temperature),
            max_tokens=kwargs.get('max_tokens', self.config.max_tokens),
            stream=True,
        )
        for chunk in stream:
            delta = chunk.choices[0].delta.content
            if delta:
                yield delta

    def chat_with_tools(self, messages: List[Dict[str, Any]],
                        tools: List[Dict[str, Any]], **kwargs) -> LLMResult:
        """One tool-calling turn against the OpenAI chat API."""
        started = time.perf_counter()
        response = self.client.chat.completions.create(
            model=self.config.model,
            messages=messages,
            tools=tools,
            temperature=kwargs.get('temperature', self.config.temperature),
            max_tokens=kwargs.get('max_tokens', self.config.max_tokens),
        )
        message = response.choices[0].message
        tool_calls = [
            {
                "id": call.id,
                "name": call.function.name,
                "arguments": call.function.arguments,
            }
            for call in (message.tool_calls or [])
        ]
        return LLMResult(
            text=message.content or "",
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
            tool_calls=tool_calls,
        )

    def get_embedding(self, text: str) -> list:
        """Get embedding using OpenAI."""
        try:
            response = self.client.embeddings.create(
                model=os.getenv('OPENAI_EMBEDDING_MODEL', 'text-embedding-3-small'),
                input=text
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"OpenAI embedding error: {e}")
            raise


class OllamaClient(BaseLLMClient):
    """Ollama local LLM client.

    This is the default, privacy-preserving backend: everything runs against a
    local daemon, so no prompt or scan finding leaves the machine.

    Talks to Ollama's REST API directly with ``requests`` rather than through
    the ``ollama`` Python package. That removes a dependency, honours
    OLLAMA_BASE_URL (the package's module-level helpers always target
    localhost), and keeps the client working on installs where the daemon is
    present but the Python package is not.
    """

    supports_tools = True

    def __init__(self, config: LLMConfig):
        """Initialize Ollama client."""
        super().__init__(config)
        self.base_url = (
            config.base_url or os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        ).rstrip('/')
        self._session = None

        if LLMFactory.is_cloud_model(config.model):
            logger.warning(
                "Ollama model '%s' is a CLOUD model: prompts and scan findings "
                "will be sent to Ollama's servers, not processed locally. Set "
                "OLLAMA_MODEL to a local model to keep inference on-machine.",
                config.model,
            )

    @property
    def session(self):
        """Reused HTTP session, so we do not reopen a socket per token."""
        if self._session is None:
            import requests
            self._session = requests.Session()
        return self._session

    def _post(self, path: str, payload: Dict[str, Any], stream: bool = False):
        """POST to the Ollama API, raising a clear error when it is unreachable."""
        import requests

        try:
            response = self.session.post(
                f"{self.base_url}{path}",
                json=payload,
                timeout=self.config.request_timeout,
                stream=stream,
            )
        except requests.exceptions.ConnectionError as e:
            raise LLMUnavailableError(
                f"Cannot reach Ollama at {self.base_url}. Start it with "
                f"'ollama serve', or set OLLAMA_BASE_URL. ({e})"
            ) from e
        except requests.exceptions.Timeout as e:
            raise LLMUnavailableError(
                f"Ollama timed out after {self.config.request_timeout}s. Large "
                f"models on CPU can exceed this; raise LLM_TIMEOUT. ({e})"
            ) from e

        if response.status_code == 404:
            raise LLMUnavailableError(
                f"Ollama has no model '{self.config.model}'. "
                f"Install it with: ollama pull {self.config.model}"
            )
        response.raise_for_status()
        return response

    def _options(self, **kwargs) -> Dict[str, Any]:
        """Build Ollama generation options.

        Previously none of these were sent, so temperature and max_tokens were
        silently ignored and the context window stayed at Ollama's 2048-token
        default — short enough to truncate the retrieved documents out of the
        prompt before the model ever saw them.
        """
        return {
            "temperature": kwargs.get('temperature', self.config.temperature),
            "num_predict": kwargs.get('max_tokens', self.config.max_tokens),
            "num_ctx": kwargs.get('context_window', self.config.context_window),
            "top_p": kwargs.get('top_p', 0.9),
            "repeat_penalty": kwargs.get('repeat_penalty', 1.1),
        }

    @staticmethod
    def _messages(prompt: str, system: Optional[str]) -> List[Dict[str, str]]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return messages

    def _payload(self, prompt: str, system: Optional[str], stream: bool,
                 **kwargs) -> Dict[str, Any]:
        """Build a /api/chat request body.

        Reasoning models (qwen3, deepseek-r1, gpt-oss and similar) stream their
        chain of thought into ``message.thinking`` and only fill
        ``message.content`` once reasoning finishes. With a bounded
        ``num_predict`` that budget is often spent entirely on thinking, and the
        answer comes back empty. Thinking is therefore disabled by default —
        grounded extraction from retrieved context does not need it, and it
        roughly halves latency. Re-enable with LLM_THINKING=1.
        """
        payload: Dict[str, Any] = {
            "model": self.config.model,
            "messages": self._messages(prompt, system),
            "options": self._options(**kwargs),
            "stream": stream,
        }
        if not self.thinking_enabled:
            payload["think"] = False
        return payload

    @property
    def thinking_enabled(self) -> bool:
        """Whether to let reasoning models emit a chain of thought."""
        return os.getenv('LLM_THINKING', '0').lower() in ('1', 'true', 'yes')

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """Generate text using Ollama."""
        result = self.generate_detailed(prompt, system=system, **kwargs)
        if result.error:
            raise LLMUnavailableError(result.error)
        return result.text

    def generate_detailed(self, prompt: str, system: Optional[str] = None,
                          **kwargs) -> LLMResult:
        started = time.perf_counter()

        def _call():
            return self._post(
                "/api/chat", self._payload(prompt, system, stream=False, **kwargs)
            ).json()

        try:
            data = self._retry(_call, "Ollama generation")
            message = data.get('message', {}) or {}
            text = message.get('content', '') or ''

            if not text.strip():
                text = self._recover_empty_answer(
                    data, message, prompt, system, **kwargs
                )

            return LLMResult(
                text=strip_reasoning(text),
                model=self.config.model,
                provider=self.config.provider,
                latency_ms=round((time.perf_counter() - started) * 1000, 1),
                # Ollama reports these natively; surfacing them makes prompt
                # budgeting and evaluation measurable rather than guesswork.
                prompt_tokens=data.get('prompt_eval_count'),
                completion_tokens=data.get('eval_count'),
            )
        except LLMUnavailableError:
            raise
        except Exception as e:
            logger.error(f"Ollama generation error: {e}")
            raise LLMUnavailableError(
                f"Ollama request failed at {self.base_url} using model "
                f"'{self.config.model}': {e}"
            ) from e

    def _recover_empty_answer(self, data: Dict[str, Any], message: Dict[str, Any],
                              prompt: str, system: Optional[str], **kwargs) -> str:
        """Salvage a response whose ``content`` came back empty.

        Almost always a reasoning model that exhausted its token budget while
        thinking. One retry with thinking off and a larger budget recovers a
        real answer; silently returning "" would surface to the user as a blank
        chat bubble with no explanation.
        """
        done_reason = data.get('done_reason')
        thinking = (message.get('thinking') or '').strip()

        if not thinking and done_reason != 'length':
            return ''

        logger.warning(
            "Model '%s' returned empty content (done_reason=%s, thinking=%d chars). "
            "Retrying with thinking disabled and a larger token budget.",
            self.config.model, done_reason, len(thinking),
        )

        retry_kwargs = dict(kwargs)
        retry_kwargs['max_tokens'] = max(
            int(kwargs.get('max_tokens', self.config.max_tokens)) * 2, 1024
        )
        payload = self._payload(prompt, system, stream=False, **retry_kwargs)
        payload["think"] = False

        try:
            retry_data = self._post("/api/chat", payload).json()
            recovered = (retry_data.get('message', {}) or {}).get('content', '') or ''
            if recovered.strip():
                return recovered
        except Exception as e:
            logger.warning("Retry after empty content also failed: %s", e)

        if thinking:
            logger.warning(
                "Falling back to the model's reasoning text; consider a "
                "non-reasoning model or raise LLM_MAX_TOKENS."
            )
            return thinking

        raise LLMUnavailableError(
            f"Model '{self.config.model}' produced no answer "
            f"(done_reason={done_reason}). Raise LLM_MAX_TOKENS or choose a "
            f"different model."
        )

    def stream(self, prompt: str, system: Optional[str] = None,
               **kwargs) -> Iterator[str]:
        """Stream tokens from Ollama as they are produced."""
        import json as _json

        response = self._post(
            "/api/chat",
            self._payload(prompt, system, stream=True, **kwargs),
            stream=True,
        )

        for line in response.iter_lines():
            if not line:
                continue
            try:
                chunk = _json.loads(line)
            except ValueError:
                continue
            piece = chunk.get('message', {}).get('content', '')
            if piece:
                yield piece
            if chunk.get('done'):
                break

    def chat_with_tools(self, messages: List[Dict[str, Any]],
                        tools: List[Dict[str, Any]], **kwargs) -> LLMResult:
        """Run one tool-calling turn against Ollama.

        Requires a tool-capable local model (qwen2.5-coder, qwen3, llama3.1+,
        mistral-nemo and similar). Models without tool support ignore the
        `tools` field and simply answer in prose.
        """
        started = time.perf_counter()
        data = self._post("/api/chat", {
            "model": self.config.model,
            "messages": messages,
            "tools": tools,
            "options": self._options(**kwargs),
            "stream": False,
        }).json()

        message = data.get('message', {})
        tool_calls = []
        for call in message.get('tool_calls', []) or []:
            fn = call.get('function', {})
            tool_calls.append({
                "id": call.get('id', fn.get('name', '')),
                "name": fn.get('name', ''),
                "arguments": fn.get('arguments', {}),
            })

        return LLMResult(
            text=message.get('content', '') or "",
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
            prompt_tokens=data.get('prompt_eval_count'),
            completion_tokens=data.get('eval_count'),
            tool_calls=tool_calls,
        )

    def get_embedding(self, text: str) -> list:
        """Get embedding using Ollama.

        Uses a dedicated embedding model, never the chat model: asking a chat
        model for embeddings returns vectors that do not encode similarity in
        any usable way.
        """
        model = os.getenv('OLLAMA_EMBEDDING_MODEL', 'nomic-embed-text')
        data = self._post("/api/embeddings", {
            "model": model,
            "prompt": text,
        }).json()
        return data['embedding']

class RemoteModelResolverMixin:
    """Recovers when a configured cloud model no longer exists.

    Providers retire model names on their own schedule, which turns a working
    install into a hard 404 with no code change on our side. Rather than
    pinning a name that will rot, this queries the provider's live catalogue
    and picks the best available match, once, on first 404.
    """

    #: Substrings of models that cannot serve chat (speech, image, embedding,
    #: safety classifiers, and similar).
    NON_CHAT_MARKERS: Tuple[str, ...] = (
        'whisper', 'tts', 'orpheus', 'embedding', 'embed', 'guard',
        'image', 'lyria', 'veo', 'robotics', 'computer-use', 'imagen',
        'nano-banana', 'safeguard',
    )

    #: Preferred models in order; first live match wins.
    PREFERRED_MODELS: Tuple[str, ...] = ()

    def _list_remote_models(self) -> List[str]:
        """Return chat-capable model IDs from the provider. Subclass hook."""
        raise NotImplementedError

    def _is_chat_model(self, model_id: str) -> bool:
        lowered = model_id.lower()
        return not any(marker in lowered for marker in self.NON_CHAT_MARKERS)

    def resolve_model(self) -> Optional[str]:
        """Pick a live model to replace one the provider no longer serves."""
        try:
            models = [m for m in self._list_remote_models() if self._is_chat_model(m)]
        except Exception as e:
            logger.warning("Could not list models for %s: %s",
                           self.config.provider, e)
            return None

        if not models:
            return None

        for preferred in self.PREFERRED_MODELS:
            for model in models:
                if preferred in model.lower():
                    return model
        return models[0]

    def _recover_from_missing_model(self) -> bool:
        """Swap in a live model. Returns True if the config was updated."""
        if getattr(self, '_model_resolved', False):
            return False
        self._model_resolved = True

        replacement = self.resolve_model()
        if not replacement or replacement == self.config.model:
            return False

        logger.warning(
            "%s no longer serves model '%s'; switching to '%s'. "
            "Set %s_MODEL to pin a different one.",
            self.config.provider, self.config.model, replacement,
            self.config.provider.upper(),
        )
        self.config.model = replacement
        return True


class GeminiClient(RemoteModelResolverMixin, BaseLLMClient):
    """Google Gemini client (Generative Language API).

    Uses the REST API directly with ``requests`` rather than the
    google-generativeai SDK, keeping the dependency surface identical to the
    other cloud backends. Gemini's free tier covers the flash models, which are
    fast enough to serve interactive chat.
    """

    supports_tools = True

    DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta"

    #: Flash tiers first: they are on the free tier and fast enough for chat.
    #: The "-latest" aliases are preferred because pinned version numbers get
    #: retired (gemini-2.5-flash already 404s on current keys).
    PREFERRED_MODELS = (
        'gemini-flash-latest',
        'gemini-3.5-flash',
        'gemini-3.1-flash-lite',
        'gemini-flash-lite-latest',
        'gemini-pro-latest',
    )

    def __init__(self, config: LLMConfig):
        """Initialize Gemini client."""
        super().__init__(config)
        self.base_url = (config.base_url or self.DEFAULT_ENDPOINT).rstrip('/')
        self._session = None
        self._model_resolved = False

    def _list_remote_models(self) -> List[str]:
        """List Gemini models that support generateContent."""
        import requests

        response = self.session.get(
            f"{self.base_url}/models",
            headers={"x-goog-api-key": self.config.api_key},
            timeout=30,
        )
        response.raise_for_status()
        return [
            entry["name"].removeprefix("models/")
            for entry in response.json().get("models", [])
            if "generateContent" in entry.get("supportedGenerationMethods", [])
        ]

    @property
    def session(self):
        """Reused HTTP session."""
        if self._session is None:
            import requests
            self._session = requests.Session()
        return self._session

    def _post(self, path: str, payload: Dict[str, Any]):
        """POST to the Gemini API with actionable error messages."""
        import requests

        if not self.config.api_key:
            raise LLMUnavailableError(
                "GEMINI_API_KEY is not set. Get a free key at "
                "https://aistudio.google.com/apikey"
            )

        try:
            response = self.session.post(
                f"{self.base_url}{path}",
                json=payload,
                # Sent as a header rather than a query parameter so the key does
                # not leak into proxy logs or error messages.
                headers={"x-goog-api-key": self.config.api_key},
                timeout=self.config.request_timeout,
            )
        except requests.exceptions.RequestException as e:
            raise LLMUnavailableError(f"Cannot reach the Gemini API: {e}") from e

        if response.status_code == 429:
            raise LLMUnavailableError(
                "Gemini rate limit reached (free tier). Wait and retry, or "
                "switch provider with LLM_PROVIDER."
            )
        if response.status_code in (401, 403):
            raise LLMUnavailableError(
                f"Gemini rejected the API key ({response.status_code}). "
                f"Check GEMINI_API_KEY."
            )
        if response.status_code == 404:
            # The model was retired or renamed. Resolve a live one and retry
            # once against the same operation.
            if '/models/' in path and self._recover_from_missing_model():
                operation = path.rsplit(':', 1)[-1]
                return self._post(f"/models/{self.config.model}:{operation}", payload)
            raise LLMUnavailableError(
                f"Gemini has no model '{self.config.model}' and no replacement "
                f"could be resolved. See https://ai.google.dev/gemini-api/docs/models"
            )
        if response.status_code >= 500:
            # Google returns 503 when a model is momentarily overloaded. This is
            # transient, so it is surfaced as retryable rather than fatal.
            raise LLMUnavailableError(
                f"Gemini is temporarily unavailable ({response.status_code}) for "
                f"model '{self.config.model}'. This is usually transient overload."
            )
        response.raise_for_status()
        return response

    def _generation_config(self, **kwargs) -> Dict[str, Any]:
        return {
            "temperature": kwargs.get('temperature', self.config.temperature),
            "maxOutputTokens": kwargs.get('max_tokens', self.config.max_tokens),
            "topP": kwargs.get('top_p', 0.9),
        }

    @staticmethod
    def _extract_text(data: Dict[str, Any]) -> str:
        """Pull the answer out of a Gemini response.

        Gemini returns content as a list of parts, and can return a candidate
        with no parts at all when generation is cut short or filtered, so each
        layer is unwrapped defensively.
        """
        candidates = data.get('candidates') or []
        if not candidates:
            feedback = data.get('promptFeedback', {})
            if feedback.get('blockReason'):
                raise LLMUnavailableError(
                    f"Gemini blocked the prompt: {feedback['blockReason']}"
                )
            return ""

        candidate = candidates[0]
        parts = (candidate.get('content') or {}).get('parts') or []
        text = "".join(part.get('text', '') for part in parts)

        if not text and candidate.get('finishReason') == 'MAX_TOKENS':
            raise LLMUnavailableError(
                "Gemini hit the output token limit before producing text. "
                "Raise LLM_MAX_TOKENS."
            )
        return text

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """Generate text using Gemini."""
        return self.generate_detailed(prompt, system=system, **kwargs).text

    def generate_detailed(self, prompt: str, system: Optional[str] = None,
                          **kwargs) -> LLMResult:
        started = time.perf_counter()

        payload: Dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": self._generation_config(**kwargs),
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

        data = self._retry(
            lambda: self._post(
                f"/models/{self.config.model}:generateContent", payload
            ).json(),
            "Gemini generation",
        )

        usage = data.get('usageMetadata', {})
        return LLMResult(
            text=strip_reasoning(self._extract_text(data)),
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
            prompt_tokens=usage.get('promptTokenCount'),
            completion_tokens=usage.get('candidatesTokenCount'),
        )

    def stream(self, prompt: str, system: Optional[str] = None,
               **kwargs) -> Iterator[str]:
        """Stream tokens from Gemini via server-sent events."""
        import json as _json

        payload: Dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": self._generation_config(**kwargs),
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

        import requests
        response = self.session.post(
            f"{self.base_url}/models/{self.config.model}:streamGenerateContent?alt=sse",
            json=payload,
            headers={"x-goog-api-key": self.config.api_key},
            timeout=self.config.request_timeout,
            stream=True,
        )
        response.raise_for_status()

        for line in response.iter_lines():
            if not line or not line.startswith(b"data: "):
                continue
            try:
                chunk = _json.loads(line[len(b"data: "):])
            except ValueError:
                continue
            for candidate in chunk.get('candidates', []):
                for part in (candidate.get('content') or {}).get('parts', []):
                    if part.get('text'):
                        yield part['text']

    def chat_with_tools(self, messages: List[Dict[str, Any]],
                        tools: List[Dict[str, Any]], **kwargs) -> LLMResult:
        """One tool-calling turn against Gemini.

        Accepts OpenAI-shaped tool definitions and converts them to Gemini's
        functionDeclarations format, so callers use one schema everywhere.
        """
        started = time.perf_counter()

        declarations = []
        for tool in tools:
            fn = tool.get('function', tool)
            declarations.append({
                "name": fn.get('name'),
                "description": fn.get('description', ''),
                "parameters": fn.get('parameters', {"type": "object", "properties": {}}),
            })

        contents = []
        system_text = None
        for message in messages:
            role = message.get('role')
            if role == 'system':
                system_text = message.get('content')
                continue
            contents.append({
                "role": "model" if role == 'assistant' else "user",
                "parts": [{"text": message.get('content', '')}],
            })

        payload: Dict[str, Any] = {
            "contents": contents,
            "tools": [{"functionDeclarations": declarations}],
            "generationConfig": self._generation_config(**kwargs),
        }
        if system_text:
            payload["systemInstruction"] = {"parts": [{"text": system_text}]}

        data = self._post(
            f"/models/{self.config.model}:generateContent", payload
        ).json()

        tool_calls = []
        for candidate in data.get('candidates', []):
            for part in (candidate.get('content') or {}).get('parts', []):
                call = part.get('functionCall')
                if call:
                    tool_calls.append({
                        "id": call.get('name', ''),
                        "name": call.get('name', ''),
                        "arguments": call.get('args', {}),
                    })

        usage = data.get('usageMetadata', {})
        return LLMResult(
            text=self._extract_text(data) if not tool_calls else "",
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
            prompt_tokens=usage.get('promptTokenCount'),
            completion_tokens=usage.get('candidatesTokenCount'),
            tool_calls=tool_calls,
        )

    def get_embedding(self, text: str) -> list:
        """Get an embedding from Gemini's free embedding model."""
        model = os.getenv('GEMINI_EMBEDDING_MODEL', 'text-embedding-004')
        data = self._post(f"/models/{model}:embedContent", {
            "model": f"models/{model}",
            "content": {"parts": [{"text": text}]},
        }).json()
        return data['embedding']['values']


class GroqClient(RemoteModelResolverMixin, BaseLLMClient):
    """Groq cloud LLM client.

    Groq exposes an OpenAI-compatible API, but this client speaks to it over
    plain HTTP with ``requests`` rather than pulling in the ``openai`` SDK —
    which the project used without declaring, so selecting Groq on a clean
    install failed with ImportError.
    """

    supports_tools = True

    DEFAULT_ENDPOINT = "https://api.groq.com/openai/v1"
    SIGNUP_URL = "https://console.groq.com/keys"

    PREFERRED_MODELS = (
        'gpt-oss-120b',
        'qwen3',
        'gpt-oss-20b',
        'llama-3.3-70b',
        'compound',
    )

    def __init__(self, config: LLMConfig):
        """Initialize Groq client."""
        super().__init__(config)
        self.base_url = (config.base_url or self.DEFAULT_ENDPOINT).rstrip('/')
        self._session = None
        self._model_resolved = False

    def _list_remote_models(self) -> List[str]:
        """List models this Groq account can call."""
        response = self.session.get(
            f"{self.base_url}/models",
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            timeout=30,
        )
        response.raise_for_status()
        return [entry["id"] for entry in response.json().get("data", [])]

    @property
    def session(self):
        """Reused HTTP session."""
        if self._session is None:
            import requests
            self._session = requests.Session()
        return self._session

    def _post(self, path: str, payload: Dict[str, Any], stream: bool = False):
        """POST to the Groq API with actionable error messages."""
        import requests

        if not self.config.api_key:
            raise LLMUnavailableError(
                f"{self.config.provider.upper()}_API_KEY is not set. "
                f"See {self.SIGNUP_URL}"
            )

        try:
            response = self.session.post(
                f"{self.base_url}{path}",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=self.config.request_timeout,
                stream=stream,
            )
        except requests.exceptions.RequestException as e:
            raise LLMUnavailableError(
                f"Cannot reach the {self.config.provider} API: {e}"
            ) from e

        if response.status_code == 429:
            raise LLMUnavailableError(
                f"{self.config.provider} rate limit reached (free tier). Wait and "
                f"retry, or switch provider with LLM_PROVIDER."
            )
        if response.status_code == 401:
            raise LLMUnavailableError(
                f"{self.config.provider} rejected the API key. Check "
                f"{self.config.provider.upper()}_API_KEY."
            )
        if response.status_code == 404:
            # Groq retires models frequently; resolve a live one and retry once.
            if self._recover_from_missing_model():
                payload = dict(payload, model=self.config.model)
                return self._post(path, payload, stream=stream)
            raise LLMUnavailableError(
                f"{self.config.provider} has no model '{self.config.model}' and no "
                f"replacement could be resolved. See {self.SIGNUP_URL}"
            )
        if response.status_code >= 500:
            # Transient upstream overload, not a configuration problem.
            raise LLMUnavailableError(
                f"{self.config.provider} is temporarily unavailable "
                f"({response.status_code}) for model '{self.config.model}'."
            )
        response.raise_for_status()
        return response

    @staticmethod
    def _messages(prompt: str, system: Optional[str]) -> List[Dict[str, str]]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return messages

    def _body(self, messages: List[Dict[str, Any]], stream: bool,
              **kwargs) -> Dict[str, Any]:
        return {
            "model": self.config.model,
            "messages": messages,
            "temperature": kwargs.get('temperature', self.config.temperature),
            "max_tokens": kwargs.get('max_tokens', self.config.max_tokens),
            "stream": stream,
        }

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """Generate text using Groq."""
        return self.generate_detailed(prompt, system=system, **kwargs).text

    def generate_detailed(self, prompt: str, system: Optional[str] = None,
                          **kwargs) -> LLMResult:
        started = time.perf_counter()

        data = self._retry(
            lambda: self._post(
                "/chat/completions",
                self._body(self._messages(prompt, system), stream=False, **kwargs),
            ).json(),
            "Groq generation",
        )

        usage = data.get('usage', {})
        choice = (data.get('choices') or [{}])[0]
        return LLMResult(
            text=strip_reasoning((choice.get('message') or {}).get('content') or ""),
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
            prompt_tokens=usage.get('prompt_tokens'),
            completion_tokens=usage.get('completion_tokens'),
        )

    def stream(self, prompt: str, system: Optional[str] = None,
               **kwargs) -> Iterator[str]:
        """Stream tokens from Groq."""
        import json as _json

        response = self._post(
            "/chat/completions",
            self._body(self._messages(prompt, system), stream=True, **kwargs),
            stream=True,
        )

        for line in response.iter_lines():
            if not line or not line.startswith(b"data: "):
                continue
            body = line[len(b"data: "):]
            if body.strip() == b"[DONE]":
                break
            try:
                chunk = _json.loads(body)
            except ValueError:
                continue
            delta = ((chunk.get('choices') or [{}])[0].get('delta') or {})
            if delta.get('content'):
                yield delta['content']

    def chat_with_tools(self, messages: List[Dict[str, Any]],
                        tools: List[Dict[str, Any]], **kwargs) -> LLMResult:
        """One tool-calling turn against Groq's OpenAI-compatible API."""
        started = time.perf_counter()

        body = self._body(messages, stream=False, **kwargs)
        body["tools"] = tools
        data = self._post("/chat/completions", body).json()

        choice = (data.get('choices') or [{}])[0]
        message = choice.get('message') or {}
        tool_calls = [
            {
                "id": call.get('id', ''),
                "name": (call.get('function') or {}).get('name', ''),
                "arguments": (call.get('function') or {}).get('arguments', ''),
            }
            for call in (message.get('tool_calls') or [])
        ]

        usage = data.get('usage', {})
        return LLMResult(
            text=message.get('content') or "",
            model=self.config.model,
            provider=self.config.provider,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
            prompt_tokens=usage.get('prompt_tokens'),
            completion_tokens=usage.get('completion_tokens'),
            tool_calls=tool_calls,
        )

    def get_embedding(self, text: str) -> list:
        """Groq serves no embedding models.

        The previous implementation called an OpenAI embedding model through
        the Groq endpoint, which always fails. Embeddings come from
        EmbeddingService instead.
        """
        raise NotImplementedError(
            "Groq does not provide an embeddings endpoint. Set EMBEDDING_PROVIDER "
            "to 'local' (default), 'gemini', or 'ollama'."
        )

class OpenRouterClient(GroqClient):
    """OpenRouter client, restricted to zero-cost models.

    OpenRouter aggregates hundreds of models behind one OpenAI-compatible API.
    Only models that cost nothing are ever selected: the catalogue is filtered
    on the pricing fields the API itself reports, rather than on the ":free"
    name suffix, since the suffix is a naming convention and not a guarantee.
    That filtering is what keeps an accidental paid request impossible.

    Inherits the request/response handling from GroqClient — both speak the
    OpenAI chat-completions dialect.
    """

    supports_tools = True

    DEFAULT_ENDPOINT = "https://openrouter.ai/api/v1"
    SIGNUP_URL = "https://openrouter.ai/keys"

    #: Preferred free models, best first. Larger instruct models lead, since
    #: grounded extraction from retrieved context rewards instruction-following.
    PREFERRED_MODELS = (
        'gpt-oss-20b',
        'nemotron-3-ultra',
        'nemotron-3-super',
        'gemma-4-31b',
        'gemma-4-26b',
        'nemotron-3.5-lightning',
        'nemotron-3-nano',
        'laguna-s',
    )

    #: Extra exclusions beyond the shared markers: music generation, safety
    #: classifiers and vision-only endpoints cannot answer a security question.
    NON_CHAT_MARKERS = RemoteModelResolverMixin.NON_CHAT_MARKERS + (
        'content-safety', 'lyria', 'north-mini-code', '-vl',
    )

    def _list_remote_models(self) -> List[str]:
        """List OpenRouter models that are free to call.

        The models endpoint needs no authentication, so this works even before
        a key is configured.
        """
        response = self.session.get(f"{self.base_url}/models", timeout=60)
        response.raise_for_status()

        free_models = []
        for entry in response.json().get("data", []):
            pricing = entry.get("pricing") or {}
            try:
                prompt_cost = float(pricing.get("prompt", "1") or 1)
                completion_cost = float(pricing.get("completion", "1") or 1)
            except (TypeError, ValueError):
                continue
            if prompt_cost == 0 and completion_cost == 0:
                free_models.append(entry["id"])

        logger.info("OpenRouter: %d free models available", len(free_models))
        return free_models

    def _post(self, path: str, payload: Dict[str, Any], stream: bool = False):
        """POST to OpenRouter, refusing anything that is not a free model."""
        model = payload.get("model", self.config.model)
        if model and not self._is_free_model(model):
            raise LLMUnavailableError(
                f"Refusing to call OpenRouter model '{model}': it is not free. "
                f"This client only uses zero-cost models."
            )
        return super()._post(path, payload, stream=stream)

    def _is_free_model(self, model: str) -> bool:
        """Whether a model is known to be free.

        Falls back to the ":free" suffix only when the catalogue cannot be
        fetched, so a network blip does not silently permit a paid call to an
        arbitrary model.
        """
        try:
            return model in self._list_remote_models()
        except Exception:
            return model.endswith(":free") or model == "openrouter/free"

    @property
    def session(self):
        """Session carrying OpenRouter's attribution headers."""
        if self._session is None:
            import requests
            self._session = requests.Session()
            self._session.headers.update({
                # Optional but recommended by OpenRouter for request attribution.
                "HTTP-Referer": os.getenv(
                    "OPENROUTER_SITE_URL", "http://localhost:5173"
                ),
                "X-Title": os.getenv("OPENROUTER_APP_NAME", "VulnDetectRAG"),
            })
        return self._session

    def get_embedding(self, text: str) -> list:
        """OpenRouter exposes no free embedding endpoint."""
        raise NotImplementedError(
            "OpenRouter does not provide embeddings here. Set EMBEDDING_PROVIDER "
            "to 'local' (default) or 'ollama'."
        )


class NvidiaClient(GroqClient):
    """NVIDIA NIM client (build.nvidia.com free tier).

    NVIDIA's hosted inference endpoint is OpenAI-compatible, so this inherits
    request handling from GroqClient and only overrides the endpoint and the
    model catalogue.
    """

    supports_tools = True

    DEFAULT_ENDPOINT = "https://integrate.api.nvidia.com/v1"
    SIGNUP_URL = "https://build.nvidia.com"

    #: Preferred models, best first: large instruct models that follow the
    #: grounding rules well, then smaller/faster ones.
    PREFERRED_MODELS = (
        'llama-3.3-70b',
        'llama-3.1-70b',
        'nemotron',
        'qwen2.5-coder',
        'mixtral-8x22b',
        'llama-3.1-8b',
    )

    NON_CHAT_MARKERS = RemoteModelResolverMixin.NON_CHAT_MARKERS + (
        'rerank', 'retrieval', 'ocr', 'vila', 'nvclip', 'parakeet',
        'riva', 'fastpitch', 'stable-diffusion', 'sdxl', 'segment',
    )

    def _list_remote_models(self) -> List[str]:
        """List models this NVIDIA account can call."""
        response = self.session.get(
            f"{self.base_url}/models",
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            timeout=60,
        )
        response.raise_for_status()
        return [entry["id"] for entry in response.json().get("data", [])]


class HuggingFaceClient(BaseLLMClient):
    """Hugging Face Inference API client."""

    def __init__(self, config: LLMConfig):
        """Initialize Hugging Face client."""
        super().__init__(config)
        self.base_url = config.base_url or "https://api-inference.huggingface.co/models"

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        """Generate text using Hugging Face."""
        try:
            import requests

            full_prompt = f"{system}\n\n{prompt}" if system else prompt
            headers = {"Authorization": f"Bearer {self.config.api_key}"}
            payload = {
                "inputs": full_prompt,
                "parameters": {
                    "temperature": kwargs.get('temperature', self.config.temperature),
                    "max_new_tokens": kwargs.get('max_tokens', self.config.max_tokens),
                    "return_full_text": False,
                }
            }

            response = requests.post(
                f"{self.base_url}/{self.config.model}",
                headers=headers,
                json=payload,
                timeout=self.config.request_timeout,
            )

            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list):
                    return result[0].get('generated_text', '')
                return result.get('generated_text', '')
            raise Exception(
                f"HuggingFace API error {response.status_code}: {response.text[:200]}"
            )

        except Exception as e:
            logger.error(f"HuggingFace generation error: {e}")
            raise

    def get_embedding(self, text: str) -> list:
        """Get embedding using Hugging Face."""
        try:
            import requests

            headers = {"Authorization": f"Bearer {self.config.api_key}"}

            response = requests.post(
                f"{self.base_url}/sentence-transformers/all-MiniLM-L6-v2",
                headers=headers,
                json={"inputs": text},
                timeout=30
            )

            if response.status_code == 200:
                return response.json()[0]
            raise Exception(f"HuggingFace embedding error: {response.status_code}")

        except Exception as e:
            logger.error(f"HuggingFace embedding error: {e}")
            raise


class LLMFactory:
    """Factory for creating LLM clients."""

    #: Local models known to handle instruction-following and tool calling
    #: well, best first. Used when auto-selecting a model.
    PREFERRED_OLLAMA_MODELS = (
        'qwen3-coder',
        'qwen2.5-coder',
        'qwen3',
        'qwen2.5',
        'llama3.3',
        'llama3.1',
        'llama3.2',
        'mistral-nemo',
        'mistral',
        'gemma3',
        'phi4',
    )

    #: Models that cannot serve as the chat backend. Vision/embedding models
    #: appear in `ollama list` alongside chat models, and picking one silently
    #: produces useless answers rather than a clear error.
    UNSUITABLE_MODEL_MARKERS = (
        'embed',        # nomic-embed-text, mxbai-embed-large, ...
        'llava',        # vision
        'moondream',    # vision
        'bakllava',     # vision
        'clip',
        'minilm',
        'rerank',
        'whisper',      # speech
    )

    @staticmethod
    def check_ollama_available(refresh: bool = False) -> dict:
        """Check if Ollama is running and detect available models.

        Talks to the HTTP API rather than shelling out to ``ollama list``, so it
        also works when the daemon is remote or the CLI is not on PATH.

        The result is cached, because this is called several times while
        serving a single page: ``/api/providers`` calls it directly and again
        inside the provider loop, and ``is_configured('ollama')`` calls it once
        more. Uncached, with Ollama not running, each of those waited on its
        own connection failure and the dashboard spent tens of seconds probing
        a daemon that was already known to be down.

        Failures are cached for longer than successes. A refused connection is
        a stable fact for as long as nobody starts the daemon, whereas an
        available daemon can gain or lose models, so the two deserve different
        TTLs. Pass ``refresh=True`` to force a probe -- the UI's explicit
        "recheck" path should, since the user is asking precisely because they
        just started Ollama.
        """
        cached = _OLLAMA_STATUS_CACHE.get("entry")
        if cached and not refresh:
            fetched_at, value = cached
            ttl = (_OLLAMA_UP_TTL_SECONDS if value.get("available")
                   else _OLLAMA_DOWN_TTL_SECONDS)
            if (time.time() - fetched_at) < ttl:
                # A copy, so a caller mutating the dict cannot poison the cache.
                return dict(value, models=list(value.get("models", [])))

        result = {
            "available": False,
            "model": "",
            "provider": "ollama",
            "models": [],
            "base_url": os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'),
            "supports_tools": False,
            "error": "",
        }
        try:
            # Plain HTTP against /api/tags rather than the `ollama` package or
            # the CLI: this reports accurately even when the Python package is
            # missing or the daemon is remote, which both of those miss.
            import requests

            # Separate connect and read timeouts. The old single 10s value
            # applied to the connect phase too, so an unreachable daemon held
            # the request open far longer than establishing a local TCP
            # connection could ever legitimately need.
            #
            # Retries are disabled outright. urllib3 retries a refused
            # connection by default, and because "localhost" resolves to both
            # ::1 and 127.0.0.1 on Windows the connect timeout is already paid
            # once per address; retrying multiplies that again.
            from requests.adapters import HTTPAdapter

            session = requests.Session()
            session.mount("http://", HTTPAdapter(max_retries=0))
            session.mount("https://", HTTPAdapter(max_retries=0))
            with session:
                response = session.get(
                    f"{result['base_url']}/api/tags",
                    timeout=(_OLLAMA_CONNECT_TIMEOUT, _OLLAMA_READ_TIMEOUT),
                )
            response.raise_for_status()
            listing = response.json()

            for entry in listing.get('models', []):
                name = entry.get('model') or entry.get('name')
                if name:
                    result["models"].append(name)

            if not result["models"]:
                result["error"] = (
                    "Ollama is running but has no models installed. "
                    "Run: ollama pull qwen2.5-coder:7b"
                )
                return _cache_ollama_status(result)

            configured = os.getenv('OLLAMA_MODEL')
            if configured and configured in result["models"]:
                result["model"] = configured
            else:
                result["model"] = LLMFactory._pick_best_model(result["models"])
                if configured:
                    result["error"] = (
                        f"Configured model '{configured}' is not installed; "
                        f"falling back to '{result['model']}'."
                    )

            result["available"] = True
            result["supports_tools"] = any(
                pref in result["model"]
                for pref in LLMFactory.PREFERRED_OLLAMA_MODELS
            )

        except ImportError:
            result["error"] = "The 'requests' package is not installed."
        except Exception as e:
            result["error"] = (
                f"Cannot reach Ollama at {result['base_url']}: {e}. "
                f"Start it with: ollama serve"
            )
            logger.debug("Ollama unavailable at %s: %s", result['base_url'], e)

        return _cache_ollama_status(result)

    @staticmethod
    def is_cloud_model(model: str) -> bool:
        """Whether a model tag routes to Ollama Cloud instead of local hardware.

        Ollama lists cloud-hosted models next to local ones. Running one sends
        the prompt — including scan findings — off the machine, which would
        silently break this project's privacy-first guarantee, so they are
        never auto-selected.

        Cloud tags take several shapes (``model:cloud``, ``qwen3-coder:480b-cloud``),
        so the whole tag is inspected rather than matching one exact suffix.
        """
        lowered = (model or "").lower()
        tag = lowered.split(':', 1)[1] if ':' in lowered else ''
        return lowered.endswith(':cloud') or 'cloud' in tag

    @staticmethod
    def is_chat_capable(model: str) -> bool:
        """Whether a model can plausibly serve as the chat backend."""
        lowered = model.lower()
        return not any(
            marker in lowered for marker in LLMFactory.UNSUITABLE_MODEL_MARKERS
        )

    @staticmethod
    def _pick_best_model(models: List[str]) -> str:
        """Prefer a known local instruct model over an arbitrary one.

        Blindly taking ``models[0]`` selects whatever sorts first — commonly an
        embedding model (nomic-embed-text) or a vision model (llava), neither
        of which can answer a question. Cloud-routed models are excluded so
        auto-selection can never silently leave the machine.
        """
        local_chat = [
            m for m in models
            if LLMFactory.is_chat_capable(m) and not LLMFactory.is_cloud_model(m)
        ]
        # Degrade deliberately: local chat > any local > any chat > anything.
        pool = (
            local_chat
            or [m for m in models if not LLMFactory.is_cloud_model(m)]
            or [m for m in models if LLMFactory.is_chat_capable(m)]
            or models
        )

        for preferred in LLMFactory.PREFERRED_OLLAMA_MODELS:
            for model in pool:
                if preferred in model.lower():
                    return model
        return pool[0]

    PROVIDERS = {
        'openai': OpenAIClient,
        'ollama': OllamaClient,
        'groq': GroqClient,
        'gemini': GeminiClient,
        'openrouter': OpenRouterClient,
        'nvidia': NvidiaClient,
        'huggingface': HuggingFaceClient
    }

    #: Providers tried in order when LLM_PROVIDER is unset or "auto".
    #: Cloud providers lead because they need no local model download and no
    #: GPU; Ollama trails as the offline fallback. Override with
    #: LLM_PROVIDER_ORDER, e.g. "ollama,gemini" to prioritise local inference.
    DEFAULT_PROVIDER_ORDER = ('groq', 'gemini', 'openrouter', 'nvidia', 'ollama')

    @classmethod
    def disabled_providers(cls) -> set:
        """Providers switched off at runtime.

        Backed by an environment variable so it works for the API, the eval
        script, and a bare Python session alike. Being able to disable a
        provider is what makes per-provider comparison possible: an ablation
        that cannot isolate one backend cannot attribute a result to it.
        """
        raw = os.getenv('LLM_DISABLED_PROVIDERS', '')
        return {p.strip().lower() for p in raw.split(',') if p.strip()}

    @classmethod
    def set_provider_enabled(cls, provider: str, enabled: bool) -> set:
        """Turn a provider on or off for subsequent requests.

        Returns the updated set of disabled providers.
        """
        provider = provider.lower()
        if provider not in cls.PROVIDERS:
            raise ValueError(f"Unknown provider: {provider}")

        disabled = cls.disabled_providers()
        if enabled:
            disabled.discard(provider)
        else:
            disabled.add(provider)

        os.environ['LLM_DISABLED_PROVIDERS'] = ','.join(sorted(disabled))
        # Catalogues are per-provider and cheap to rebuild; clearing avoids
        # serving a stale list for a provider that was just re-enabled.
        _MODEL_CATALOGUE_CACHE.pop(provider, None)
        logger.info("Provider '%s' %s", provider, "enabled" if enabled else "disabled")
        return disabled

    @classmethod
    def provider_order(cls) -> List[str]:
        """Resolve the provider preference list, minus anything disabled."""
        configured = os.getenv('LLM_PROVIDER_ORDER', '')
        if configured:
            order = [p.strip().lower() for p in configured.split(',') if p.strip()]
        else:
            order = list(cls.DEFAULT_PROVIDER_ORDER)

        disabled = cls.disabled_providers()
        return [p for p in order if p in cls.PROVIDERS and p not in disabled]

    @classmethod
    def is_configured(cls, provider: str) -> bool:
        """Whether a provider has what it needs to actually answer a request.

        Checked before selection so an unusable provider is skipped up front
        rather than failing on the user's first question.
        """
        provider = provider.lower()
        if provider in cls.disabled_providers():
            return False
        if provider == 'ollama':
            return cls.check_ollama_available()["available"]
        key_env = {
            'openai': 'OPENAI_API_KEY',
            'groq': 'GROQ_API_KEY',
            'gemini': 'GEMINI_API_KEY',
            'openrouter': 'OPENROUTER_API_KEY',
            'nvidia': 'NVIDIA_API_KEY',
            'huggingface': 'HUGGINGFACE_API_KEY',
        }.get(provider)
        return bool(key_env and os.getenv(key_env))

    @classmethod
    def resolve_provider(cls, provider: Optional[str] = None) -> str:
        """Pick which provider to use.

        An explicit choice is honoured even if it looks unconfigured, so the
        user gets a precise error rather than a silent substitution. Only
        "auto" (or an unset LLM_PROVIDER) walks the preference list.
        """
        requested = (provider or os.getenv('LLM_PROVIDER', 'auto')).lower()

        if requested and requested != 'auto':
            if requested not in cls.PROVIDERS:
                raise ValueError(
                    f"Unknown LLM provider: {requested}. "
                    f"Valid options: {', '.join(cls.PROVIDERS)}, auto"
                )
            return requested

        for candidate in cls.provider_order():
            if cls.is_configured(candidate):
                logger.info("Auto-selected LLM provider: %s", candidate)
                return candidate

        logger.warning(
            "No LLM provider is configured. Set GROQ_API_KEY or GEMINI_API_KEY, "
            "or install a local model with 'ollama pull qwen2.5-coder:7b'."
        )
        return cls.provider_order()[0] if cls.provider_order() else 'ollama'

    @classmethod
    def create(cls, provider: Optional[str] = None) -> BaseLLMClient:
        """Create LLM client based on configuration.

        Args:
            provider: LLM provider name

        Returns:
            LLM client instance
        """
        provider = cls.resolve_provider(provider)

        if provider == 'ollama':
            ollama_status = cls.check_ollama_available()
            default_ollama_model = (
                ollama_status["model"] if ollama_status["available"]
                else 'qwen2.5-coder:7b'
            )
        else:
            default_ollama_model = 'qwen2.5-coder:7b'

        model_map = {
            'openai': os.getenv('OPENAI_MODEL', 'gpt-4o'),
            'ollama': os.getenv('OLLAMA_MODEL', default_ollama_model),
            # llama-3.1-70b-versatile was decommissioned by Groq; 3.3 is the
            # current general-purpose model on that endpoint.
            'groq': os.getenv('GROQ_MODEL', 'openai/gpt-oss-120b'),
            # gemini-2.0-flash is on the free tier and fast enough for chat.
            'gemini': os.getenv('GEMINI_MODEL', 'gemini-flash-latest'),
            # Free tier only; the client refuses any model that costs money.
            'openrouter': os.getenv('OPENROUTER_MODEL', 'minimax/minimax-m3:free'),
            'nvidia': os.getenv('NVIDIA_MODEL', 'nvidia/nemotron-3-nano-30b-a3b'),
            'huggingface': os.getenv('HUGGINGFACE_MODEL', 'meta-llama/Llama-3.1-8B-Instruct')
        }

        # If the configured Ollama model is not actually installed, fall back to
        # one that is, rather than failing every request at generation time.
        model = model_map.get(provider, 'gpt-4o')
        if provider == 'ollama':
            status = cls.check_ollama_available()
            if status["available"] and model not in status["models"]:
                logger.warning("Ollama model '%s' not installed; using '%s'",
                               model, status["model"])
                model = status["model"]

        api_key_map = {
            'openai': os.getenv('OPENAI_API_KEY'),
            'groq': os.getenv('GROQ_API_KEY'),
            # GOOGLE_API_KEY is accepted too, matching Google's own tooling.
            'gemini': os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY'),
            'openrouter': os.getenv('OPENROUTER_API_KEY'),
            'nvidia': os.getenv('NVIDIA_API_KEY'),
            'huggingface': os.getenv('HUGGINGFACE_API_KEY')
        }

        base_url_map = {
            'ollama': os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        }

        if provider != 'ollama' and not api_key_map.get(provider):
            logger.warning(
                "%s selected but no API key is set (%s_API_KEY). "
                "Requests will fail; set the key or use LLM_PROVIDER=auto.",
                provider, provider.upper(),
            )

        config = LLMConfig(
            provider=provider,
            model=model,
            temperature=float(os.getenv('LLM_TEMPERATURE', '0.1')),
            max_tokens=int(os.getenv('LLM_MAX_TOKENS', '2000')),
            api_key=api_key_map.get(provider),
            base_url=base_url_map.get(provider),
            context_window=int(os.getenv('LLM_CONTEXT_WINDOW', '8192')),
            request_timeout=int(os.getenv('LLM_TIMEOUT', '180')),
        )

        return cls.PROVIDERS[provider](config)

    @classmethod
    def get_available_providers(cls) -> list:
        """Get list of available providers."""
        return list(cls.PROVIDERS.keys())

    @classmethod
    def list_models(cls, provider: str, refresh: bool = False) -> List[str]:
        """Every chat-capable model a provider currently offers, best first.

        Cached briefly: rotation consults this on failure, and re-querying the
        catalogue on every request would add a round trip to each answer.
        """
        provider = provider.lower()
        cached = _MODEL_CATALOGUE_CACHE.get(provider)
        if cached and not refresh and (time.time() - cached[0]) < _CATALOGUE_TTL_SECONDS:
            return cached[1]

        models: List[str] = []
        try:
            if provider == 'ollama':
                status = cls.check_ollama_available()
                models = [
                    m for m in status.get('models', [])
                    if cls.is_chat_capable(m) and not cls.is_cloud_model(m)
                ]
                models.sort(key=lambda m: cls._preference_rank(
                    m, cls.PREFERRED_OLLAMA_MODELS))
            elif provider in ('groq', 'gemini', 'openrouter', 'nvidia'):
                client = cls.create(provider)
                models = [
                    m for m in client._list_remote_models()
                    if client._is_chat_model(m)
                ]
                models.sort(key=lambda m: cls._preference_rank(
                    m, client.PREFERRED_MODELS))
        except Exception as e:
            logger.warning("Could not list %s models: %s", provider, e)

        if models:
            _MODEL_CATALOGUE_CACHE[provider] = (time.time(), models)
        return models

    @staticmethod
    def _preference_rank(model: str, preferred: Tuple[str, ...]) -> int:
        """Sort key placing preferred models first, unknown ones last."""
        lowered = model.lower()
        for index, name in enumerate(preferred):
            if name in lowered:
                return index
        return len(preferred)


#: Cache of live model catalogues, so rotation does not re-query the provider
#: on every request. (provider -> (fetched_at, [model_ids]))
_MODEL_CATALOGUE_CACHE: Dict[str, Tuple[float, List[str]]] = {}
_CATALOGUE_TTL_SECONDS = 900

#: Cache of the last Ollama probe. ("entry" -> (fetched_at, status_dict))
#: A single-key dict rather than a bare global so the value can be replaced
#: atomically from any thread without a lock: dict item assignment is one
#: bytecode, and a reader either sees the old tuple or the new one.
_OLLAMA_STATUS_CACHE: Dict[str, Tuple[float, dict]] = {}

#: An available daemon can gain or lose models between calls, so its status is
#: held only briefly. A refused connection stays refused until someone starts
#: the daemon, so it is held longer -- that is the case that was costing whole
#: seconds per request.
_OLLAMA_UP_TTL_SECONDS = 30
_OLLAMA_DOWN_TTL_SECONDS = 120

#: Connecting to a daemon on localhost either succeeds immediately or is
#: refused immediately; anything slower is a daemon that is not there. Kept low
#: because "localhost" resolves to both ::1 and 127.0.0.1 on Windows and the
#: connect timeout is paid once per address, so the wall-clock cost of a cold
#: probe against a stopped daemon is roughly twice this value. The read timeout
#: is separate and more generous, since listing many models is real work.
_OLLAMA_CONNECT_TIMEOUT = 0.6
_OLLAMA_READ_TIMEOUT = 8.0


def _cache_ollama_status(result: dict) -> dict:
    """Store an Ollama probe result and return it.

    Logging happens here rather than at the call site so it fires on a change
    of state instead of once per probe. The old code logged a warning every
    time the check ran, which -- called several times per page load against a
    daemon that was not running -- produced pages of identical stack traces
    that buried anything worth reading.
    """
    previous = _OLLAMA_STATUS_CACHE.get("entry")
    was_available = previous[1].get("available") if previous else None
    now_available = bool(result.get("available"))

    if was_available != now_available:
        if now_available:
            logger.info("Ollama available at %s (model '%s')",
                        result.get("base_url"), result.get("model"))
        elif result.get("error"):
            logger.warning("Ollama unavailable: %s", result["error"])

    _OLLAMA_STATUS_CACHE["entry"] = (time.time(), result)
    return result


class ModelRotatingClient(BaseLLMClient):
    """One provider, every model it offers, tried in order until one answers.

    Free tiers rate-limit per model, and providers retire model names without
    notice. Pinning a single model therefore fails for reasons unrelated to the
    question. This walks the provider's live catalogue instead: a model that
    errors is put in cooldown and the next is tried, and the first model that
    succeeds becomes the preferred one for later calls.
    """

    #: How long a failing model is skipped before being retried.
    COOLDOWN_SECONDS = 300

    def __init__(self, provider: str, models: List[str], config: LLMConfig):
        super().__init__(config)
        self.provider = provider
        self.models = models or [config.model]
        self._cooldown: Dict[str, float] = {}
        self._preferred = 0
        self._clients: Dict[str, BaseLLMClient] = {}

    @property
    def supports_tools(self) -> bool:  # type: ignore[override]
        return LLMFactory.PROVIDERS[self.provider].supports_tools

    def _client_for(self, model: str) -> BaseLLMClient:
        """Build (and cache) a single-model client for this provider."""
        if model not in self._clients:
            config = LLMConfig(
                provider=self.provider,
                model=model,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                api_key=self.config.api_key,
                base_url=self.config.base_url,
                context_window=self.config.context_window,
                request_timeout=self.config.request_timeout,
                # Rotation is the retry strategy here, so per-model retries are
                # kept low: a rate-limited model should yield to the next model
                # rather than sleeping through a backoff.
                max_retries=0,
            )
            self._clients[model] = LLMFactory.PROVIDERS[self.provider](config)
        return self._clients[model]

    def _candidates(self) -> List[str]:
        """Models worth trying now, preferred first, skipping those cooling down."""
        now = time.time()
        ordered = self.models[self._preferred:] + self.models[:self._preferred]
        ready = [m for m in ordered if self._cooldown.get(m, 0) <= now]
        # If everything is cooling down, ignore cooldowns rather than refusing
        # to answer at all.
        return ready or ordered

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        result = self.generate_detailed(prompt, system=system, **kwargs)
        if result.error:
            raise LLMUnavailableError(result.error)
        return result.text

    def generate_detailed(self, prompt: str, system: Optional[str] = None,
                          **kwargs) -> LLMResult:
        errors: List[str] = []

        for model in self._candidates():
            try:
                result = self._client_for(model).generate_detailed(
                    prompt, system=system, **kwargs
                )
                if result.error:
                    raise LLMUnavailableError(result.error)
                if not (result.text or "").strip():
                    raise LLMUnavailableError("empty response")

                if self.models.index(model) != self._preferred:
                    logger.info("%s: now preferring model '%s'", self.provider, model)
                    self._preferred = self.models.index(model)
                self.config.model = model
                return result

            except Exception as e:
                self._cooldown[model] = time.time() + self.COOLDOWN_SECONDS
                errors.append(f"{model}: {e}")
                logger.warning("%s model '%s' failed, rotating: %s",
                               self.provider, model, e)

        return LLMResult(
            text="",
            model=self.config.model,
            provider=self.provider,
            error=f"All {len(self.models)} {self.provider} models failed. "
                  + " | ".join(errors[:4]),
        )

    def stream(self, prompt: str, system: Optional[str] = None,
               **kwargs) -> Iterator[str]:
        last_error: Optional[Exception] = None
        for model in self._candidates():
            try:
                yielded = False
                for piece in self._client_for(model).stream(
                    prompt, system=system, **kwargs
                ):
                    yielded = True
                    yield piece
                if yielded:
                    self.config.model = model
                    return
            except Exception as e:
                last_error = e
                self._cooldown[model] = time.time() + self.COOLDOWN_SECONDS
                logger.warning("%s streaming model '%s' failed, rotating: %s",
                               self.provider, model, e)
        raise LLMUnavailableError(f"All {self.provider} models failed: {last_error}")

    def chat_with_tools(self, messages: List[Dict[str, Any]],
                        tools: List[Dict[str, Any]], **kwargs) -> LLMResult:
        last_error: Optional[Exception] = None
        for model in self._candidates():
            try:
                result = self._client_for(model).chat_with_tools(
                    messages, tools, **kwargs
                )
                self.config.model = model
                return result
            except Exception as e:
                last_error = e
                self._cooldown[model] = time.time() + self.COOLDOWN_SECONDS
                logger.warning("%s tool call on '%s' failed, rotating: %s",
                               self.provider, model, e)
        raise LLMUnavailableError(f"All {self.provider} models failed: {last_error}")

    def get_embedding(self, text: str) -> list:
        return self._client_for(self._candidates()[0]).get_embedding(text)


class EnsembleLLMClient(BaseLLMClient):
    """Queries several providers at once and reconciles them into one answer.

    Groq and Gemini are asked the same grounded question in parallel. Two
    independent models working from the same retrieved context disagree mainly
    where the context is thin or ambiguous, so reconciling them surfaces
    exactly the claims that deserve doubt — and a single provider being
    rate-limited stops mattering, because the other still answers.

    Modes (LLM_ENSEMBLE_MODE):
      synthesize  merge both answers with a second, cheap LLM call (default)
      fastest     return whichever answered first
      longest     return the most detailed answer, no extra call
    """

    SYNTHESIS_SYSTEM = """You merge two independent expert answers into one.

Rules:
1. Keep only claims that appear in at least one answer. Add nothing new.
2. Preserve [Doc N] citations exactly as given.
3. Where the two answers agree, state the claim once, plainly.
4. Where they disagree on a fact (a CVSS score, a version, a date), say so
   explicitly and give both values rather than silently picking one.
5. If both answers say the information is unavailable, say that and stop.
6. Output only the merged answer. Never mention that you merged anything, and
   never refer to "Answer A", "Answer B", or the merging process."""

    def __init__(self, clients: List[BaseLLMClient], mode: Optional[str] = None,
                 timeout: int = 120):
        if not clients:
            raise ValueError("EnsembleLLMClient requires at least one client")
        super().__init__(clients[0].config)
        self.clients = clients
        self.mode = (mode or os.getenv('LLM_ENSEMBLE_MODE', 'synthesize')).lower()
        self.timeout = timeout

    @property
    def supports_tools(self) -> bool:  # type: ignore[override]
        return any(c.supports_tools for c in self.clients)

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        result = self.generate_detailed(prompt, system=system, **kwargs)
        if result.error:
            raise LLMUnavailableError(result.error)
        return result.text

    def generate_detailed(self, prompt: str, system: Optional[str] = None,
                          **kwargs) -> LLMResult:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        started = time.perf_counter()
        successes: List[LLMResult] = []
        errors: List[str] = []

        # Neither a `with` block nor an uncaught as_completed timeout: one
        # provider that hangs instead of erroring (an unreachable host blocking
        # until its read timeout) would otherwise discard the answers of every
        # provider that did respond. as_completed raises TimeoutError out of
        # the loop, and the executor's context manager then blocks on shutdown
        # waiting for the stuck thread — so a single slow member turned a
        # working ensemble into a total failure that fell through to Ollama.
        pool = ThreadPoolExecutor(max_workers=len(self.clients))
        try:
            futures = {
                pool.submit(c.generate_detailed, prompt, system=system, **kwargs): c
                for c in self.clients
            }
            try:
                for future in as_completed(futures, timeout=self.timeout):
                    client = futures[future]
                    try:
                        result = future.result()
                        if result.error or not (result.text or "").strip():
                            raise LLMUnavailableError(result.error or "empty response")
                        successes.append(result)
                    except Exception as e:
                        errors.append(f"{client.config.provider}: {e}")
                        logger.warning("Ensemble member %s failed: %s",
                                       client.config.provider, e)
            except TimeoutError:
                stalled = [futures[f].config.provider
                           for f in futures if not f.done()]
                errors.append(f"timed out after {self.timeout}s: {', '.join(stalled)}")
                logger.warning(
                    "Ensemble timed out after %ss; continuing with %d of %d "
                    "providers (stalled: %s)",
                    self.timeout, len(successes), len(self.clients),
                    ", ".join(stalled),
                )
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        if not successes:
            return LLMResult(
                text="", model=self.config.model, provider="ensemble",
                latency_ms=round((time.perf_counter() - started) * 1000, 1),
                error="All ensemble providers failed. " + " | ".join(errors),
            )

        # Preserve the order the providers were configured in, so a given set of
        # inputs always merges the same way.
        order = {id(c): i for i, c in enumerate(self.clients)}
        successes.sort(key=lambda r: order.get(
            id(next((c for c in self.clients
                     if c.config.provider == r.provider), None)), 99))

        if len(successes) == 1 or self.mode == 'fastest':
            chosen = successes[0]
            return self._tag(chosen, successes, started, errors)

        if self.mode == 'longest':
            chosen = max(successes, key=lambda r: len(r.text))
            return self._tag(chosen, successes, started, errors)

        return self._synthesize(successes, started, errors, **kwargs)

    def _synthesize(self, results: List[LLMResult], started: float,
                    errors: List[str], **kwargs) -> LLMResult:
        """Merge candidate answers with one extra LLM call."""
        parts = []
        for i, result in enumerate(results, 1):
            parts.append(f"--- Answer {i} (from {result.provider}) ---\n{result.text}")
        merge_prompt = (
            "Merge these answers to the same question into a single answer.\n\n"
            + "\n\n".join(parts)
        )

        for client in self.clients:
            try:
                merged = client.generate_detailed(
                    merge_prompt,
                    system=self.SYNTHESIS_SYSTEM,
                    max_tokens=kwargs.get('max_tokens', self.config.max_tokens),
                    temperature=0.0,
                )
                if merged.error or not (merged.text or "").strip():
                    continue

                total_prompt = sum(r.prompt_tokens or 0 for r in results)
                total_completion = sum(r.completion_tokens or 0 for r in results)
                return LLMResult(
                    text=merged.text,
                    model="+".join(sorted({r.model for r in results})),
                    provider="ensemble(" + "+".join(r.provider for r in results) + ")",
                    latency_ms=round((time.perf_counter() - started) * 1000, 1),
                    prompt_tokens=total_prompt + (merged.prompt_tokens or 0),
                    completion_tokens=total_completion + (merged.completion_tokens or 0),
                )
            except Exception as e:
                logger.warning("Synthesis via %s failed: %s", client.config.provider, e)

        # Synthesis is an enhancement; if it fails, the best single answer is
        # still a correct result.
        logger.warning("Ensemble synthesis failed; returning the longest answer")
        return self._tag(max(results, key=lambda r: len(r.text)), results, started, errors)

    @staticmethod
    def _tag(chosen: LLMResult, all_results: List[LLMResult], started: float,
             errors: List[str]) -> LLMResult:
        """Return one member's answer, labelled with how many members ran."""
        return LLMResult(
            text=chosen.text,
            model=chosen.model,
            provider=(
                chosen.provider if len(all_results) == 1
                else f"ensemble/{chosen.provider}"
            ),
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
            prompt_tokens=chosen.prompt_tokens,
            completion_tokens=chosen.completion_tokens,
        )

    def stream(self, prompt: str, system: Optional[str] = None,
               **kwargs) -> Iterator[str]:
        """Stream from the first member that produces tokens.

        Streaming and cross-provider synthesis are incompatible: a merged
        answer cannot exist until both members have finished.
        """
        last_error: Optional[Exception] = None
        for client in self.clients:
            try:
                yielded = False
                for piece in client.stream(prompt, system=system, **kwargs):
                    yielded = True
                    yield piece
                if yielded:
                    return
            except Exception as e:
                last_error = e
                logger.warning("Ensemble streaming via %s failed: %s",
                               client.config.provider, e)
        raise LLMUnavailableError(f"All ensemble providers failed: {last_error}")

    def chat_with_tools(self, messages: List[Dict[str, Any]],
                        tools: List[Dict[str, Any]], **kwargs) -> LLMResult:
        """Tool calls go to a single member — merging side effects is unsafe."""
        last_error: Optional[Exception] = None
        for client in self.clients:
            if not client.supports_tools:
                continue
            try:
                return client.chat_with_tools(messages, tools, **kwargs)
            except Exception as e:
                last_error = e
                logger.warning("Ensemble tool call via %s failed: %s",
                               client.config.provider, e)
        raise LLMUnavailableError(f"No ensemble provider could run tools: {last_error}")

    def get_embedding(self, text: str) -> list:
        return self.clients[0].get_embedding(text)


class FallbackLLMClient(BaseLLMClient):
    """Tries several providers in order until one answers.

    Free API tiers rate-limit and local daemons stop, so a single hard-wired
    provider makes the assistant fail outright for reasons unrelated to the
    user's question. This routes to the next configured provider instead, and
    remembers which one worked so subsequent calls skip the dead ones.
    """

    def __init__(self, clients: List[BaseLLMClient]):
        if not clients:
            raise ValueError("FallbackLLMClient requires at least one client")
        super().__init__(clients[0].config)
        self.clients = clients
        self._active_index = 0

    @property
    def supports_tools(self) -> bool:  # type: ignore[override]
        return self.active.supports_tools

    @property
    def active(self) -> BaseLLMClient:
        """The client currently believed to be healthy."""
        return self.clients[self._active_index]

    def _ordered(self) -> List[Tuple[int, BaseLLMClient]]:
        """Active client first, then the rest as fallbacks."""
        order = list(enumerate(self.clients))
        return order[self._active_index:] + order[:self._active_index]

    def generate(self, prompt: str, system: Optional[str] = None, **kwargs) -> str:
        result = self.generate_detailed(prompt, system=system, **kwargs)
        if result.error:
            raise LLMUnavailableError(result.error)
        return result.text

    def generate_detailed(self, prompt: str, system: Optional[str] = None,
                          **kwargs) -> LLMResult:
        errors: List[str] = []

        for index, client in self._ordered():
            try:
                result = client.generate_detailed(prompt, system=system, **kwargs)
                if result.error:
                    raise LLMUnavailableError(result.error)
                if index != self._active_index:
                    logger.info(
                        "Switched LLM provider to %s (%s)",
                        client.config.provider, client.config.model,
                    )
                    self._active_index = index
                    self.config = client.config
                return result
            except Exception as e:
                errors.append(f"{client.config.provider}: {e}")
                logger.warning(
                    "Provider %s failed, trying next: %s", client.config.provider, e
                )

        joined = " | ".join(errors)
        return LLMResult(
            text="",
            model=self.config.model,
            provider=self.config.provider,
            error=f"All LLM providers failed. {joined}",
        )

    def stream(self, prompt: str, system: Optional[str] = None,
               **kwargs) -> Iterator[str]:
        last_error: Optional[Exception] = None
        for index, client in self._ordered():
            try:
                yielded = False
                for piece in client.stream(prompt, system=system, **kwargs):
                    yielded = True
                    yield piece
                if yielded:
                    self._active_index = index
                    self.config = client.config
                    return
            except Exception as e:
                last_error = e
                logger.warning(
                    "Streaming from %s failed, trying next: %s",
                    client.config.provider, e,
                )
        raise LLMUnavailableError(f"All LLM providers failed: {last_error}")

    def chat_with_tools(self, messages: List[Dict[str, Any]],
                        tools: List[Dict[str, Any]], **kwargs) -> LLMResult:
        last_error: Optional[Exception] = None
        for index, client in self._ordered():
            if not client.supports_tools:
                continue
            try:
                result = client.chat_with_tools(messages, tools, **kwargs)
                self._active_index = index
                self.config = client.config
                return result
            except Exception as e:
                last_error = e
                logger.warning(
                    "Tool call via %s failed, trying next: %s",
                    client.config.provider, e,
                )
        raise LLMUnavailableError(f"No provider could run tools: {last_error}")

    def get_embedding(self, text: str) -> list:
        return self.active.get_embedding(text)


#: Providers treated as "cloud" for orchestration purposes. These are asked in
#: parallel; Ollama is held back as the offline last resort.
CLOUD_PROVIDERS = ('groq', 'gemini', 'openrouter', 'nvidia')


def _build_rotating_client(provider: str) -> Optional[BaseLLMClient]:
    """Build a client that rotates across every model a provider offers."""
    if not LLMFactory.is_configured(provider):
        return None

    base = LLMFactory.create(provider)
    models = LLMFactory.list_models(provider)

    # Honour an explicitly pinned model by trying it first, then rotating to the
    # rest if it is rate-limited or retired.
    pinned = {
        'groq': os.getenv('GROQ_MODEL'),
        'gemini': os.getenv('GEMINI_MODEL'),
        'openrouter': os.getenv('OPENROUTER_MODEL'),
        'nvidia': os.getenv('NVIDIA_MODEL'),
        'ollama': os.getenv('OLLAMA_MODEL'),
    }.get(provider)
    if pinned:
        models = [pinned] + [m for m in models if m != pinned]

    if not models:
        return base
    return ModelRotatingClient(provider, models, base.config)


def get_cloud_clients() -> List[BaseLLMClient]:
    """One rotating client per configured, enabled cloud provider.

    Exposed separately from get_llm_client() because the map-reduce reader
    needs the providers as *independent addressable endpoints* rather than as a
    single reconciled client: it deals out different context to each one, so it
    has to know how many there are and be able to target them individually.
    """
    order = LLMFactory.provider_order()
    return [
        client for name in order if name in CLOUD_PROVIDERS
        for client in [_build_rotating_client(name)] if client
    ]


def get_local_clients() -> List[BaseLLMClient]:
    """Rotating clients for every configured non-cloud provider (Ollama)."""
    order = LLMFactory.provider_order()
    return [
        client for name in order if name not in CLOUD_PROVIDERS
        for client in [_build_rotating_client(name)] if client
    ]


def get_llm_client(provider: Optional[str] = None) -> BaseLLMClient:
    """Build the LLM client according to the configured orchestration policy.

    Default topology:

        ┌─ Groq   (rotates across all Groq models)  ─┐
        │                                            ├─ ensemble ─┐
        └─ Gemini (rotates across all Gemini models) ┘            │
                                                                  ├─ answer
        Ollama (local, rotates across installed models) ──────────┘
               used only when both cloud providers are unreachable

    The two cloud providers are asked in parallel and their answers reconciled
    into one, so a rate-limited model, a retired model name, or a provider
    outage degrades the answer rather than blocking it. Ollama sits behind them
    as the offline path.

    Environment controls:
        LLM_PROVIDER        auto (default) or a specific provider to force
        LLM_PROVIDER_ORDER  preference order, e.g. "ollama,groq" for local-first
        LLM_ENSEMBLE        0 disables parallel querying (first healthy wins)
        LLM_ENSEMBLE_MODE   synthesize (default) | fastest | longest
        LLM_FALLBACK        0 disables failover entirely

    Args:
        provider: Optional provider override

    Returns:
        LLM client instance
    """
    explicit = (provider or os.getenv('LLM_PROVIDER', 'auto')).lower()
    fallback_enabled = os.getenv('LLM_FALLBACK', '1').lower() not in ('0', 'false', 'no')
    ensemble_enabled = os.getenv('LLM_ENSEMBLE', '1').lower() not in ('0', 'false', 'no')

    # An explicit provider is honoured exactly, with model rotation inside it
    # and (unless disabled) the other providers behind it as fallbacks.
    if explicit and explicit != 'auto':
        primary = _build_rotating_client(explicit) or LLMFactory.create(explicit)
        if not fallback_enabled:
            return primary
        backups = [
            client for name in LLMFactory.provider_order() if name != explicit
            for client in [_build_rotating_client(name)] if client
        ]
        return FallbackLLMClient([primary, *backups]) if backups else primary

    cloud = get_cloud_clients()
    local = get_local_clients()

    if not cloud and not local:
        # Nothing configured: return the default so the caller gets a clear,
        # actionable error instead of an empty chain.
        return LLMFactory.create()

    tiers: List[BaseLLMClient] = []
    if cloud:
        if len(cloud) > 1 and ensemble_enabled:
            tiers.append(EnsembleLLMClient(cloud))
            logger.info(
                "LLM orchestration: %s queried in parallel (mode=%s), "
                "reconciled into one answer",
                " + ".join(c.config.provider for c in cloud),
                os.getenv('LLM_ENSEMBLE_MODE', 'synthesize'),
            )
        else:
            tiers.extend(cloud)

    if local:
        tiers.extend(local)
        logger.info("Local fallback available: %s",
                    ", ".join(c.config.provider for c in local))

    if len(tiers) == 1 or not fallback_enabled:
        return tiers[0]
    return FallbackLLMClient(tiers)
