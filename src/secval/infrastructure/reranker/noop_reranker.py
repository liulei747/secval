"""关闭模型重排序时保留RRF排名。"""

from secval.models.search import SearchResult


class NoopReranker:
    provider_name = "none"
    model_name = None
    candidate_count = 0

    def rerank(
        self,
        query: str,
        candidates: list[SearchResult],
        top_k: int,
    ) -> list[SearchResult]:
        del query
        return candidates[:top_k]
