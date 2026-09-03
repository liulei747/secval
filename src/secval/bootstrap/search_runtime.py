"""根据统一配置创建搜索运行环境。"""

import os
from dataclasses import dataclass

from opensearchpy import OpenSearch
from qdrant_client import QdrantClient

from secval.infrastructure.embedding import (
    ApiEmbeddingModel,
    LocalEmbeddingModel,
)
from secval.infrastructure.fusion import RrfResultFusion
from secval.infrastructure.opensearch import (
    OpenSearchKeywordRetriever,
    create_code_index,
    create_open_search_connection,
)
from secval.infrastructure.qdrant import (
    QdrantVectorRetriever,
    create_code_vector_collection,
    create_qdrant_connection,
)
from secval.infrastructure.reranker import (
    LocalReranker,
    NoopReranker,
)
from secval.interfaces import EmbeddingModel, Reranker
from secval.services.search_service import SearchService
from secval.shared_config import SearchSettings, load_search_settings


@dataclass
class SearchRuntime:
    """保存搜索板块启动后可以重复使用的对象。"""

    settings: SearchSettings
    open_search_connection: OpenSearch
    qdrant_client: QdrantClient
    embedding_model: EmbeddingModel
    reranker: Reranker
    search_service: SearchService


def create_search_runtime(
    settings_path: str = "config/search.yaml",
) -> SearchRuntime:
    """读取配置，并创建连接、模型和统一搜索服务。"""

    settings = load_search_settings(settings_path)
    open_search_connection = create_open_search_connection(
        host=settings.open_search.host,
        port=settings.open_search.port,
    )
    qdrant_client = create_qdrant_connection(
        host=settings.qdrant.host,
        port=settings.qdrant.port,
    )
    # 搜索 API 即使尚未导入仓库，也应该返回空结果而不是索引不存在错误。
    create_code_index(open_search_connection)
    create_code_vector_collection(qdrant_client)
    embedding_model = _create_embedding_model(settings)
    reranker = _create_reranker(settings)
    keyword_retriever = OpenSearchKeywordRetriever(open_search_connection)
    vector_retriever = QdrantVectorRetriever(
        qdrant_client=qdrant_client,
        open_search_connection=open_search_connection,
        embedding_model=embedding_model,
    )
    search_service = SearchService(
        keyword_retriever=keyword_retriever,
        vector_retriever=vector_retriever,
        result_fusion=RrfResultFusion(),
        reranker=reranker,
        candidate_multiplier=settings.fusion.candidate_multiplier,
        max_candidate_count=settings.fusion.max_candidate_count,
    )

    return SearchRuntime(
        settings=settings,
        open_search_connection=open_search_connection,
        qdrant_client=qdrant_client,
        embedding_model=embedding_model,
        reranker=reranker,
        search_service=search_service,
    )


def _create_embedding_model(settings: SearchSettings) -> EmbeddingModel:
    """根据配置或环境变量选择本地模型与远程 API。"""

    provider = os.getenv(
        "SECVAL_EMBEDDING_PROVIDER", settings.embedding.provider
    ).strip().lower()
    if provider == "local":
        return LocalEmbeddingModel(
            model_name=settings.embedding.model_name,
            device=settings.embedding.device,
            max_sequence_length=settings.embedding.max_sequence_length,
            expected_dimension=settings.embedding.dimension,
        )
    if provider != "api":
        raise ValueError("SECVAL_EMBEDDING_PROVIDER 只能是 local 或 api")

    model_name = os.getenv(
        "SECVAL_EMBEDDING_API_MODEL", "qwen3.7-text-embedding"
    )
    dimension = int(
        os.getenv(
            "SECVAL_EMBEDDING_API_DIMENSION",
            str(settings.embedding.dimension),
        )
    )
    return ApiEmbeddingModel(
        api_url=os.getenv("SECVAL_EMBEDDING_API_URL", ""),
        api_key=os.getenv("SECVAL_EMBEDDING_API_KEY", ""),
        model_name=model_name,
        expected_dimension=dimension,
        batch_size=int(os.getenv("SECVAL_EMBEDDING_API_BATCH_SIZE", "64")),
        timeout_seconds=int(
            os.getenv("SECVAL_EMBEDDING_API_TIMEOUT_SECONDS", "120")
        ),
    )


def _create_reranker(settings: SearchSettings) -> Reranker:
    """创建关闭状态或本地CrossEncoder Reranker。"""

    config = settings.reranker
    if config.provider == "none":
        return NoopReranker()
    return LocalReranker(
        model_name=config.model_name,
        device=config.device,
        candidate_count=config.candidate_count,
        max_sequence_length=config.max_sequence_length,
        batch_size=config.batch_size,
    )
