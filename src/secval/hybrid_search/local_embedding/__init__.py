"""使用本地模型或远程 API 生成代码和查询向量。"""

from .api_embedding_model import ApiEmbeddingModel
from .embedding_model import EmbeddingModel

from .local_embedding_model import (
    EMBEDDING_DIMENSION,
    EMBEDDING_MODEL_NAME,
    LocalEmbeddingModel,
)

__all__ = [
    "EMBEDDING_DIMENSION",
    "EMBEDDING_MODEL_NAME",
    "ApiEmbeddingModel",
    "EmbeddingModel",
    "LocalEmbeddingModel",
]
