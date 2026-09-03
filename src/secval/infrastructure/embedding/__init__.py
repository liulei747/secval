"""Embedding能力的本地与远程实现。"""

from secval.interfaces import EmbeddingModel

from .api_embedding_model import ApiEmbeddingModel
from .local_embedding_model import EMBEDDING_DIMENSION, LocalEmbeddingModel

__all__ = [
    "EMBEDDING_DIMENSION",
    "ApiEmbeddingModel",
    "EmbeddingModel",
    "LocalEmbeddingModel",
]
