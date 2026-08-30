"""使用本地模型生成代码和查询向量。"""

from .local_embedding_model import (
    EMBEDDING_DIMENSION,
    EMBEDDING_MODEL_NAME,
    LocalEmbeddingModel,
)

__all__ = [
    "EMBEDDING_DIMENSION",
    "EMBEDDING_MODEL_NAME",
    "LocalEmbeddingModel",
]
