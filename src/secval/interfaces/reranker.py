"""搜索重排序器的共同接口。"""

from typing import Protocol

from secval.models.search import SearchResult


class RerankerError(RuntimeError):
    """Reranker推理失败；搜索服务捕获后回退到RRF。"""


class Reranker(Protocol):
    provider_name: str
    model_name: str | None
    candidate_count: int

    def rerank(
        self,
        query: str,
        candidates: list[SearchResult],
        top_k: int,
    ) -> list[SearchResult]: ...
