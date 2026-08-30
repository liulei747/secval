"""根据统一配置创建搜索运行环境。"""

from dataclasses import dataclass

from opensearchpy import OpenSearch
from qdrant_client import QdrantClient

from secval.hybrid_search.local_embedding import LocalEmbeddingModel
from secval.hybrid_search.open_search_storage import (
    create_open_search_connection,
)
from secval.hybrid_search.search_service import SearchService
from secval.hybrid_search.vector_storage import create_qdrant_connection
from secval.shared_config import SearchSettings, load_search_settings


@dataclass
class SearchRuntime:
    """保存搜索板块启动后可以重复使用的对象。"""

    settings: SearchSettings
    open_search_connection: OpenSearch
    qdrant_client: QdrantClient
    embedding_model: LocalEmbeddingModel
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
    embedding_model = LocalEmbeddingModel(
        model_name=settings.embedding.model_name,
        device=settings.embedding.device,
        max_sequence_length=settings.embedding.max_sequence_length,
        expected_dimension=settings.embedding.dimension,
    )
    search_service = SearchService(
        open_search_connection=open_search_connection,
        qdrant_client=qdrant_client,
        embedding_model=embedding_model,
        candidate_multiplier=settings.fusion.candidate_multiplier,
        max_candidate_count=settings.fusion.max_candidate_count,
    )

    return SearchRuntime(
        settings=settings,
        open_search_connection=open_search_connection,
        qdrant_client=qdrant_client,
        embedding_model=embedding_model,
        search_service=search_service,
    )
