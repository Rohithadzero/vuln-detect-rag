"""Embedding utilities for text vectorization."""

import os
import hashlib
import logging
from typing import List, Optional, Callable
from functools import lru_cache

logger = logging.getLogger(__name__)


class EmbeddingService:
    """Service for generating text embeddings."""
    
    #: Sensible default model per provider. Picking the model from the LLM
    #: config (as the Ollama path used to) produces garbage embeddings when the
    #: chat model is not an embedding model.
    DEFAULT_MODELS = {
        'local': 'all-MiniLM-L6-v2',
        'ollama': 'nomic-embed-text',
        'openai': 'text-embedding-3-small',
        'huggingface': 'sentence-transformers/all-MiniLM-L6-v2',
    }

    def __init__(self, provider: Optional[str] = None, model: Optional[str] = None,
                 cache: Optional['EmbeddingCache'] = None):
        """Initialize embedding service.

        Args:
            provider: Embedding provider (local, ollama, openai, huggingface)
            model: Embedding model name
            cache: Optional embedding cache
        """
        self.provider = (provider or os.getenv('EMBEDDING_PROVIDER', 'local')).lower()
        self.model = (
            model
            or os.getenv('EMBEDDING_MODEL')
            or os.getenv('LOCAL_EMBEDDING_MODEL')
            or self.DEFAULT_MODELS.get(self.provider, 'all-MiniLM-L6-v2')
        )
        self._embedding_fn: Optional[Callable] = None
        self.cache = cache if cache is not None else EmbeddingCache()

    @property
    def dimension(self) -> int:
        """Embedding dimension, discovered by embedding a probe string once."""
        if not hasattr(self, '_dimension'):
            self._dimension = len(self.embed("dimension probe"))
        return self._dimension
    
    @property
    def embedding_fn(self) -> Callable:
        """Get embedding function."""
        if self._embedding_fn is None:
            self._embedding_fn = self._get_embedding_function()
        return self._embedding_fn
    
    def _get_embedding_function(self) -> Callable:
        """Get appropriate embedding function based on provider."""
        if self.provider == 'openai':
            return self._openai_embedding
        elif self.provider == 'huggingface':
            return self._huggingface_embedding
        elif self.provider == 'ollama':
            return self._ollama_embedding
        elif self.provider == 'local':
            return self._local_embedding
        else:
            return self._local_embedding
    
    def _openai_embedding(self, text: str) -> List[float]:
        """Generate embedding using OpenAI."""
        try:
            from openai import OpenAI
            
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("OPENAI_API_KEY not set")
            
            client = OpenAI(api_key=api_key)
            
            response = client.embeddings.create(
                model=self.model,
                input=text
            )
            
            return response.data[0].embedding
            
        except ImportError:
            logger.error("OpenAI package not installed")
            raise
        except Exception as e:
            logger.error(f"OpenAI embedding error: {e}")
            raise
    
    def _huggingface_embedding(self, text: str) -> List[float]:
        """Generate embedding using Hugging Face."""
        try:
            import requests
            
            api_key = os.getenv('HUGGINGFACE_API_KEY')
            if not api_key:
                raise ValueError("HUGGINGFACE_API_KEY not set")
            
            headers = {"Authorization": f"Bearer {api_key}"}
            
            response = requests.post(
                "https://api-inference.huggingface.co/pipeline/feature-extraction",
                headers=headers,
                json={"inputs": text},
                timeout=30
            )
            
            if response.status_code == 200:
                embedding = response.json()
                if isinstance(embedding, list) and len(embedding) > 0:
                    if isinstance(embedding[0], list):
                        return embedding[0]
                    return embedding
            else:
                raise Exception(f"HuggingFace API error: {response.status_code}")
                
        except Exception as e:
            logger.error(f"HuggingFace embedding error: {e}")
            raise
    
    def _ollama_embedding(self, text: str) -> List[float]:
        """Generate embedding using Ollama.

        Honours OLLAMA_BASE_URL by constructing an explicit client — the
        module-level ``ollama.embeddings`` helper ignores it and always talks to
        localhost, which breaks any remote/containerised Ollama deployment.
        """
        try:
            import ollama

            base_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
            client = ollama.Client(host=base_url)

            response = client.embeddings(
                model=self.model or 'nomic-embed-text',
                prompt=text
            )

            return response['embedding']

        except ImportError:
            logger.error("Ollama package not installed")
            raise
        except Exception as e:
            logger.error(f"Ollama embedding error: {e}")
            raise
    
    def _local_embedding(self, text: str) -> List[float]:
        """Generate embedding using local HuggingFace sentence-transformers.

        Prefers langchain_huggingface, but falls back to sentence-transformers
        directly so the local (default, fully offline) path still works when
        only the lower-level package is installed.
        """
        if not hasattr(self, "_hf_embeddings"):
            self._hf_embeddings = self._load_local_model()
        return self._hf_embeddings.embed_query(text)

    def _load_local_model(self):
        """Load the local embedding model, caching it on the instance."""
        try:
            from langchain_huggingface import HuggingFaceEmbeddings
            logger.info("Loading local embeddings via langchain_huggingface: %s", self.model)
            return HuggingFaceEmbeddings(model_name=self.model)
        except ImportError:
            pass

        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            logger.error(
                "Neither langchain_huggingface nor sentence-transformers is installed; "
                "the local embedding provider cannot run."
            )
            raise ImportError(
                "Install sentence-transformers (or langchain-huggingface) to use "
                "EMBEDDING_PROVIDER=local"
            ) from e

        logger.info("Loading local embeddings via sentence-transformers: %s", self.model)

        class _SentenceTransformerAdapter:
            """Expose the small slice of the LangChain embeddings interface we use."""

            def __init__(self, model_name: str):
                self._model = SentenceTransformer(model_name)

            def embed_query(self, text: str) -> List[float]:
                return self._model.encode(text, normalize_embeddings=False).tolist()

            def embed_documents(self, texts: List[str]) -> List[List[float]]:
                return [
                    vector.tolist()
                    for vector in self._model.encode(
                        texts, normalize_embeddings=False, batch_size=32
                    )
                ]

        return _SentenceTransformerAdapter(self.model)
    
    def embed(self, text: str) -> List[float]:
        """Generate embedding for text, served from cache when possible.

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        cached = self.cache.get(text) if self.cache else None
        if cached is not None:
            return cached

        embedding = self.embedding_fn(text)

        if self.cache:
            self.cache.set(text, embedding)
        return embedding

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts.

        For the local sentence-transformers backend this issues a single
        batched ``embed_documents`` call, which is dramatically faster than
        embedding one string at a time during corpus indexing.

        Args:
            texts: List of texts to embed

        Returns:
            List of embedding vectors
        """
        if not texts:
            return []

        # Serve what we can from cache; only embed the misses.
        results: List[Optional[List[float]]] = [None] * len(texts)
        pending_idx: List[int] = []
        pending_txt: List[str] = []

        for i, text in enumerate(texts):
            cached = self.cache.get(text) if self.cache else None
            if cached is not None:
                results[i] = cached
            else:
                pending_idx.append(i)
                pending_txt.append(text)

        if pending_txt:
            computed = self._embed_many(pending_txt)
            for i, text, embedding in zip(pending_idx, pending_txt, computed):
                results[i] = embedding
                if self.cache:
                    self.cache.set(text, embedding)

        return [r for r in results if r is not None]

    def _embed_many(self, texts: List[str]) -> List[List[float]]:
        """Backend-specific batch embedding, falling back to a loop."""
        if self.provider == 'local':
            try:
                self._local_embedding("warmup")  # ensures _hf_embeddings exists
                return self._hf_embeddings.embed_documents(texts)
            except Exception as e:
                logger.warning(f"Batch embedding failed, falling back per-item: {e}")

        if self.provider == 'openai':
            try:
                from openai import OpenAI
                client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
                response = client.embeddings.create(model=self.model, input=texts)
                return [item.embedding for item in response.data]
            except Exception as e:
                logger.warning(f"OpenAI batch embedding failed, falling back: {e}")

        return [self.embedding_fn(text) for text in texts]

    @staticmethod
    def chunk_text(text: str, chunk_size: int = 900, overlap: int = 150) -> List[str]:
        """Split text into overlapping chunks on natural boundaries.

        Splits preferentially at paragraph breaks, then sentence ends, then
        whitespace, so a chunk rarely severs a sentence mid-clause. Overlap
        keeps context that straddles a boundary retrievable from both sides.

        Args:
            text: Text to chunk
            chunk_size: Maximum chunk size in characters
            overlap: Overlap between consecutive chunks

        Returns:
            List of text chunks
        """
        text = (text or "").strip()
        if not text:
            return []
        if len(text) <= chunk_size:
            return [text]

        overlap = min(overlap, chunk_size // 2)
        chunks: List[str] = []
        start = 0

        while start < len(text):
            end = min(start + chunk_size, len(text))

            if end < len(text):
                window_start = start + chunk_size // 2
                # Prefer paragraph break, then sentence end, then any whitespace.
                split_point = text.rfind('\n\n', window_start, end)
                if split_point == -1:
                    for terminator in ('. ', '.\n', '! ', '? '):
                        candidate = text.rfind(terminator, window_start, end)
                        if candidate > split_point:
                            split_point = candidate + len(terminator) - 1
                if split_point == -1:
                    split_point = text.rfind(' ', window_start, end)

                if split_point > start:
                    end = split_point + 1

            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)

            if end >= len(text):
                break
            start = max(end - overlap, start + 1)

        return chunks


class EmbeddingCache:
    """Cache for storing computed embeddings."""
    
    def __init__(self, max_size: int = 1000):
        """Initialize embedding cache.
        
        Args:
            max_size: Maximum cache size
        """
        self.max_size = max_size
        self._cache: dict = {}
    
    def get(self, text: str) -> Optional[List[float]]:
        """Get cached embedding.
        
        Args:
            text: Text to look up
            
        Returns:
            Cached embedding or None
        """
        key = self._hash_text(text)
        return self._cache.get(key)
    
    def set(self, text: str, embedding: List[float]) -> None:
        """Cache embedding.
        
        Args:
            text: Text key
            embedding: Embedding to cache
        """
        if len(self._cache) >= self.max_size:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        
        key = self._hash_text(text)
        self._cache[key] = embedding
    
    @staticmethod
    def _hash_text(text: str) -> str:
        """Generate hash for text."""
        return hashlib.md5(text.encode()).hexdigest()


def get_embedding_service(provider: Optional[str] = None) -> EmbeddingService:
    """Get configured embedding service.
    
    Args:
        provider: Optional provider override
        
    Returns:
        EmbeddingService instance
    """
    return EmbeddingService(provider=provider)
