"""Embedding 模型共同接口。"""

from typing import Protocol
from typing import Callable


class EmbeddingModel(Protocol):
    """索引和搜索只依赖这个接口，不关心向量来自本地还是 API。"""

    provider_name: str
    model_name: str
    expected_dimension: int

    def embed_code(
        self,
        code_texts: list[str],
        progress: Callable[[int, int], None] | None = None,
    ) -> list[list[float]]: ...

    def embed_query(self, query_text: str) -> list[float]: ...
