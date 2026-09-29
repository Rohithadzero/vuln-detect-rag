"""LLM client module: openai_client."""

import os
import time
import logging
from typing import Optional, Dict, Any, List, Iterator
from .base import BaseLLMClient, LLMConfig, LLMResult

logger = logging.getLogger(__name__)


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
