"""LLM client module: ollama_client."""

import os
import time
import logging
from typing import Optional, Dict, Any, List, Iterator
from .base import BaseLLMClient, LLMConfig, LLMResult, LLMUnavailableError, strip_reasoning

logger = logging.getLogger(__name__)


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

        from .factory import LLMFactory

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
