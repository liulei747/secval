"""使用 Qdrant 执行代码语义搜索。"""

from opensearchpy import OpenSearch
from qdrant_client import QdrantClient
from qdrant_client.http import models

from secval.infrastructure.opensearch import load_code_chunks_by_ids
from secval.infrastructure.qdrant import CODE_VECTOR_COLLECTION
from secval.interfaces import EmbeddingModel
from secval.models.identifiers import ChunkId
from secval.models.search import SearchQuery, SearchResult


class QdrantVectorRetriever:
    """使用Qdrant和Embedding模型实现向量召回能力。"""

    def __init__(
        self,
        qdrant_client: QdrantClient,
        open_search_connection: OpenSearch,
        embedding_model: EmbeddingModel,
    ) -> None:
        self.qdrant_client = qdrant_client
        self.open_search_connection = open_search_connection
        self.embedding_model = embedding_model

    def search(self, query: SearchQuery) -> list[SearchResult]:
        return search_by_vector(
            qdrant_client=self.qdrant_client,
            open_search_connection=self.open_search_connection,
            embedding_model=self.embedding_model,
            query=query,
        )


def search_by_vector(
    qdrant_client: QdrantClient,
    open_search_connection: OpenSearch,
    embedding_model: EmbeddingModel,
    query: SearchQuery,
) -> list[SearchResult]:
    """查找语义相近的向量，并读取对应的完整代码块。"""

    query_vector = embedding_model.embed_query(query.text)
    query_filter = build_vector_filter(query)
    response = qdrant_client.query_points(
        collection_name=CODE_VECTOR_COLLECTION,
        query=query_vector,
        query_filter=query_filter,
        limit=query.top_k,
        with_payload=["chunk_id"],
        with_vectors=False,
    )

    chunk_ids: list[ChunkId] = []

    for point in response.points:
        if point.payload is None or "chunk_id" not in point.payload:
            raise ValueError("Qdrant 搜索结果缺少代码块 ID")

        chunk_ids.append(ChunkId(str(point.payload["chunk_id"])))

    code_chunks = load_code_chunks_by_ids(
        open_search_connection,
        chunk_ids,
    )
    results: list[SearchResult] = []

    for result_index in range(len(response.points)):
        point = response.points[result_index]
        score = float(point.score)
        result = SearchResult(
            chunk=code_chunks[result_index],
            rank=result_index + 1,
            final_score=score,
            vector_score=score,
        )
        results.append(result)

    return results


def build_vector_filter(query: SearchQuery) -> models.Filter:
    """把 SearchQuery 中的范围条件转换成 Qdrant Filter。"""

    conditions: list[models.FieldCondition] = [
        models.FieldCondition(
            key="repository_id",
            match=models.MatchAny(any=list(query.repository_ids)),
        ),
        models.FieldCondition(
            key="snapshot_id",
            match=models.MatchAny(any=list(query.snapshot_ids)),
        ),
    ]

    if query.language is not None:
        conditions.append(
            models.FieldCondition(
                key="language",
                match=models.MatchValue(value=query.language),
            )
        )

    if query.path_prefix is not None:
        conditions.append(
            models.FieldCondition(
                key="relative_path",
                match=models.MatchPrefix(prefix=query.path_prefix),
            )
        )

    if query.chunk_type is not None:
        conditions.append(
            models.FieldCondition(
                key="chunk_type",
                match=models.MatchValue(value=query.chunk_type),
            )
        )

    return models.Filter(must=conditions)
