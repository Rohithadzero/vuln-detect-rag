"""LLM configuration and factory for multiple providers."""

import os
import time
import logging
from typing import Optional, Dict, Any, Union, List, Iterator, Callable, Tuple
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


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
                text=text,
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
                text=text,
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
            text=self._extract_text(data),
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
                "GROQ_API_KEY is not set. Get a free key at "
                "https://console.groq.com/keys"
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
            raise LLMUnavailableError(f"Cannot reach the Groq API: {e}") from e

        if response.status_code == 429:
            raise LLMUnavailableError(
                "Groq rate limit reached (free tier). Wait and retry, or switch "
                "provider with LLM_PROVIDER."
            )
        if response.status_code == 401:
            raise LLMUnavailableError("Groq rejected the API key. Check GROQ_API_KEY.")
        if response.status_code == 404:
            # Groq retires models frequently; resolve a live one and retry once.
            if self._recover_from_missing_model():
                payload = dict(payload, model=self.config.model)
                return self._post(path, payload, stream=stream)
            raise LLMUnavailableError(
                f"Groq has no model '{self.config.model}' and no replacement "
                f"could be resolved. See https://console.groq.com/docs/models"
            )
        if response.status_code >= 500:
            # Transient upstream overload, not a configuration problem.
            raise LLMUnavailableError(
                f"Groq is temporarily unavailable ({response.status_code}) for "
                f"model '{self.config.model}'."
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
            text=(choice.get('message') or {}).get('content') or "",
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
    def check_ollama_available() -> dict:
        """Check if Ollama is running and detect available models.

        Talks to the HTTP API rather than shelling out to ``ollama list``, so it
        also works when the daemon is remote or the CLI is not on PATH.
        """
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

            response = requests.get(f"{result['base_url']}/api/tags", timeout=10)
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
                return result

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
            logger.warning("Failed to check Ollama availability: %s", e)

        return result

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
        'huggingface': HuggingFaceClient
    }

    #: Providers tried in order when LLM_PROVIDER is unset or "auto".
    #: Cloud providers lead because they need no local model download and no
    #: GPU; Ollama trails as the offline fallback. Override with
    #: LLM_PROVIDER_ORDER, e.g. "ollama,gemini" to prioritise local inference.
    DEFAULT_PROVIDER_ORDER = ('groq', 'gemini', 'ollama')

    @classmethod
    def provider_order(cls) -> List[str]:
        """Resolve the provider preference list."""
        configured = os.getenv('LLM_PROVIDER_ORDER', '')
        if configured:
            order = [p.strip().lower() for p in configured.split(',') if p.strip()]
        else:
            order = list(cls.DEFAULT_PROVIDER_ORDER)
        return [p for p in order if p in cls.PROVIDERS]

    @classmethod
    def is_configured(cls, provider: str) -> bool:
        """Whether a provider has what it needs to actually answer a request.

        Checked before selection so an unusable provider is skipped up front
        rather than failing on the user's first question.
        """
        provider = provider.lower()
        if provider == 'ollama':
            return cls.check_ollama_available()["available"]
        key_env = {
            'openai': 'OPENAI_API_KEY',
            'groq': 'GROQ_API_KEY',
            'gemini': 'GEMINI_API_KEY',
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


def get_llm_client(provider: Optional[str] = None) -> BaseLLMClient:
    """Get configured LLM client.

    With no explicit provider (or LLM_PROVIDER=auto), returns a client that
    falls through the configured providers in preference order, so one being
    rate-limited or offline does not take the assistant down. Set
    LLM_FALLBACK=0 to force a single provider.

    Args:
        provider: Optional provider override

    Returns:
        LLM client instance
    """
    explicit = provider or os.getenv('LLM_PROVIDER', 'auto').lower()
    fallback_enabled = os.getenv('LLM_FALLBACK', '1').lower() not in ('0', 'false', 'no')

    if explicit and explicit != 'auto':
        primary = LLMFactory.create(explicit)
        if not fallback_enabled:
            return primary
        others = [
            LLMFactory.create(name)
            for name in LLMFactory.provider_order()
            if name != explicit and LLMFactory.is_configured(name)
        ]
        return FallbackLLMClient([primary, *others]) if others else primary

    configured = [
        name for name in LLMFactory.provider_order() if LLMFactory.is_configured(name)
    ]
    if not configured:
        # Nothing is set up; return the default so the caller gets a clear,
        # actionable error from that provider rather than an empty chain.
        return LLMFactory.create()

    clients = [LLMFactory.create(name) for name in configured]
    if len(clients) == 1 or not fallback_enabled:
        return clients[0]
    return FallbackLLMClient(clients)
