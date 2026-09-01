"""提供统一的混合搜索入口。"""

from opensearchpy import OpenSearch
from qdrant_client import QdrantClient

from secval.hybrid_search.keyword_search import search_by_keywords
from secval.hybrid_search.local_embedding import LocalEmbeddingModel
from secval.hybrid_search.result_fusion import fuse_with_rrf
from secval.hybrid_search.search_models import SearchQuery, SearchResult
from secval.hybrid_search.vector_search import search_by_vector

FUSION_CANDIDATE_MULTIPLIER = 3
MAX_CANDIDATE_COUNT = 100


class SearchService:
    """依次执行关键词搜索、向量搜索和 RRF 合并。"""

    def __init__(
        self,
        open_search_connection: OpenSearch,
        qdrant_client: QdrantClient,
        embedding_model: LocalEmbeddingModel,
        candidate_multiplier: int = FUSION_CANDIDATE_MULTIPLIER,
        max_candidate_count: int = MAX_CANDIDATE_COUNT,
    ) -> None:
        """保存可以重复使用的连接和 Embedding 模型。"""

        self.open_search_connection = open_search_connection
        self.qdrant_client = qdrant_client
        self.embedding_model = embedding_model
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

        keyword_results = search_by_keywords(
            connection=self.open_search_connection,
            query=candidate_query,
        )
        vector_results = search_by_vector(
            qdrant_client=self.qdrant_client,
            open_search_connection=self.open_search_connection,
            embedding_model=self.embedding_model,
            query=candidate_query,
        )

        return fuse_with_rrf(
            keyword_results=keyword_results,
            vector_results=vector_results,
            top_k=query.top_k,
        )


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
