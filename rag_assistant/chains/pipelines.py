"""Specialised RAG pipelines and the cached pipeline factory."""

import logging
from typing import Dict, List

from .rag_chain import RAGPipeline

logger = logging.getLogger(__name__)


class VulnerabilityRAGPipeline(RAGPipeline):
    """Specialized RAG pipeline for vulnerability analysis."""

    @classmethod
    def create_remediation_chain(cls) -> 'VulnerabilityRAGPipeline':
        """Create pipeline optimized for remediation queries."""
        pipeline = cls()
        pipeline.SYSTEM_PROMPT = """You are a vulnerability remediation specialist.

GROUNDING RULES (these override everything else):
1. Base every recommendation on the numbered context documents below, citing them as [Doc N].
2. Never invent patch versions, configuration keys, or vendor advisories. If the context lacks a fix, say so.
3. If the context is empty, say the knowledge base has no entry rather than guessing.

Focus on:
1. Step-by-step remediation guidance
2. Prioritizing by severity and exploitability
3. Compensating controls when an immediate fix is not possible
4. Configuration examples where the context supports them
5. Dependencies and prerequisites for each fix

For each recommendation: explain the vulnerability and its risk, give specific steps, and note any operational impact or side effects."""
        return pipeline

    @classmethod
    def create_exploit_analysis_chain(cls) -> 'VulnerabilityRAGPipeline':
        """Create pipeline optimized for exploit analysis."""
        pipeline = cls()
        pipeline.SYSTEM_PROMPT = """You are an exploit analysis specialist supporting authorized defensive security work.

GROUNDING RULES (these override everything else):
1. Base your analysis on the numbered context documents below, citing them as [Doc N].
2. Never invent CVE IDs, affected versions, or exploit availability. If the context lacks it, say so.
3. If the context is empty, say the knowledge base has no entry rather than guessing.

Focus on:
1. How the vulnerability works technically
2. Affected systems and versions
3. Attack vectors and preconditions
4. Exploitability and whether public exploit code exists
5. Detection and mitigation strategies

Explain mechanisms at a conceptual level and prioritize detection signatures and defensive guidance. Do not produce working exploit code."""
        return pipeline

    @classmethod
    def create_attack_path_chain(cls) -> 'VulnerabilityRAGPipeline':
        """Create pipeline optimized for attack path analysis."""
        pipeline = cls()
        pipeline.SYSTEM_PROMPT = """You are a network attack path analyst.

GROUNDING RULES (these override everything else):
1. Base every hop you describe on the numbered context documents below, citing them as [Doc N].
2. Never invent hosts, services, or vulnerabilities that are not in the context.
3. If the context is empty, say the knowledge base has no entry rather than guessing.

Focus on:
1. Modeling plausible attack chains from the observed findings
2. Identifying pivot points and lateral movement opportunities
3. Assessing privilege escalation paths
4. Evaluating network segmentation effectiveness
5. Recommending controls that break the chain

For each path: map source to target, identify intermediate hops, analyze service relationships, and suggest the single most effective disruption point."""
        return pipeline


#: Pipelines are cached per type. Each construction loads an embedding model and
#: opens the vector store, so rebuilding one per request was pure overhead.
_PIPELINE_CACHE: Dict[str, RAGPipeline] = {}


def get_rag_pipeline(pipeline_type: str = 'default') -> RAGPipeline:
    """Get configured RAG pipeline.

    Args:
        pipeline_type: Type of pipeline (default, remediation, exploit, attack_path)

    Returns:
        Configured RAG pipeline
    """
    pipeline_type = (pipeline_type or 'default').lower()

    if pipeline_type in _PIPELINE_CACHE:
        return _PIPELINE_CACHE[pipeline_type]

    builders = {
        'remediation': VulnerabilityRAGPipeline.create_remediation_chain,
        'exploit': VulnerabilityRAGPipeline.create_exploit_analysis_chain,
        'attack_path': VulnerabilityRAGPipeline.create_attack_path_chain,
    }

    if pipeline_type not in builders and pipeline_type != 'default':
        raise ValueError(
            f"Unknown pipeline type '{pipeline_type}'. "
            f"Valid: default, {', '.join(builders)}"
        )

    pipeline = builders[pipeline_type]() if pipeline_type in builders else RAGPipeline()

    # Specialized pipelines differ only by system prompt, so they can share the
    # default pipeline's loaded embedding model and vector store handle.
    if pipeline_type != 'default' and 'default' in _PIPELINE_CACHE:
        base = _PIPELINE_CACHE['default']
        pipeline.vector_store = base.vector_store
        pipeline.embedding_service = base.embedding_service
        pipeline.conversation_memory = base.conversation_memory

    _PIPELINE_CACHE[pipeline_type] = pipeline
    return pipeline


def reset_pipelines() -> None:
    """Drop cached pipelines so the next call rebuilds them.

    Needed whenever the LLM topology changes — enabling or disabling a
    provider, or switching model — because a cached pipeline holds a client
    built from the previous configuration and would keep using it.
    """
    _PIPELINE_CACHE.clear()
    logger.info("RAG pipeline cache cleared; clients will be rebuilt")


def available_pipelines() -> List[str]:
    """List the selectable pipeline types."""
    return ['default', 'remediation', 'exploit', 'attack_path']
