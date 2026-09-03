"""多路搜索结果融合能力接口。"""

from typing import Protocol

from secval.models.search import SearchResult


class ResultFusion(Protocol):
    """把关键词和向量候选合并为统一排名。"""

    def fuse(
        self,
        keyword_results: list[SearchResult],
        vector_results: list[SearchResult],
        top_k: int,
    ) -> list[SearchResult]: ...
