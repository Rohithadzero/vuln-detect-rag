"""LLM client module: composite."""

import os
import time
import logging
from typing import Optional, Dict, Any, List, Iterator, Tuple
from .factory import LLMFactory
from .base import BaseLLMClient, LLMConfig, LLMResult, LLMUnavailableError

logger = logging.getLogger(__name__)


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
