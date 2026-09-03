"""提供统一的混合搜索入口。"""

import logging

from secval.interfaces import (
    KeywordRetriever,
    Reranker,
    RerankerError,
    ResultFusion,
    VectorRetriever,
)
from secval.models.search import SearchQuery, SearchResult

FUSION_CANDIDATE_MULTIPLIER = 3
MAX_CANDIDATE_COUNT = 100
logger = logging.getLogger(__name__)


class SearchService:
    """依次执行关键词搜索、向量搜索和 RRF 合并。"""

    def __init__(
        self,
        keyword_retriever: KeywordRetriever,
        vector_retriever: VectorRetriever,
        result_fusion: ResultFusion,
        reranker: Reranker,
        candidate_multiplier: int = FUSION_CANDIDATE_MULTIPLIER,
        max_candidate_count: int = MAX_CANDIDATE_COUNT,
    ) -> None:
        """保存四个可替换的搜索能力。"""

        self.keyword_retriever = keyword_retriever
        self.vector_retriever = vector_retriever
        self.result_fusion = result_fusion
        self.reranker = reranker
        if candidate_multiplier < 1:
            raise ValueError("候选召回倍数必须大于或等于 1")

        if max_candidate_count < 1:
            raise ValueError("最大候选数量必须大于或等于 1")

        self.candidate_multiplier = candidate_multiplier
        self.max_candidate_count = max_candidate_count

    def search(self, query: SearchQuery) -> list[SearchResult]:
        """执行两路召回，并返回 RRF 合并后的 Top K。"""

        candidate_query = _create_candidate_query(
            query,
            self.candidate_multiplier,
            self.max_candidate_count,
        )

        keyword_results = self.keyword_retriever.search(candidate_query)
        vector_results = self.vector_retriever.search(candidate_query)

        rerank_candidate_count = max(
            query.top_k,
            self.reranker.candidate_count,
        )
        fused_results = self.result_fusion.fuse(
            keyword_results=keyword_results,
            vector_results=vector_results,
            top_k=rerank_candidate_count,
        )
        try:
            return self.reranker.rerank(
                query=query.text,
                candidates=fused_results,
                top_k=query.top_k,
            )
        except RerankerError:
            logger.exception("Reranker失败，回退到RRF结果")
            return fused_results[: query.top_k]


def _create_candidate_query(
    query: SearchQuery,
    candidate_multiplier: int,
    max_candidate_count: int,
) -> SearchQuery:
    """复制查询，并把内部召回数量扩大到最终数量的三倍。"""

    candidate_count = query.top_k * candidate_multiplier
    candidate_count = min(candidate_count, max_candidate_count)

    return SearchQuery(
        text=query.text,
        repository_ids=list(query.repository_ids),
        snapshot_ids=list(query.snapshot_ids),
        top_k=candidate_count,
        language=query.language,
        path_prefix=query.path_prefix,
        chunk_type=query.chunk_type,
    )
