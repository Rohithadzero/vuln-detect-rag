"""LLM client module: remote_clients."""

import os
import time
import logging
from typing import Optional, Dict, Any, List, Iterator, Tuple
from .base import BaseLLMClient, LLMConfig, LLMResult, LLMUnavailableError, strip_reasoning

logger = logging.getLogger(__name__)


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
