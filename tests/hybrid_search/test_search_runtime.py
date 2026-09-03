from unittest.mock import MagicMock, patch

from secval.bootstrap.search_runtime import create_search_runtime
from secval.shared_config import (
    EmbeddingSettings,
    FusionSettings,
    RerankerSettings,
    SearchSettings,
    ServiceAddress,
)


@patch("secval.bootstrap.search_runtime.SearchService")
@patch("secval.bootstrap.search_runtime.LocalEmbeddingModel")
@patch("secval.bootstrap.search_runtime.create_code_vector_collection")
@patch("secval.bootstrap.search_runtime.create_code_index")
@patch("secval.bootstrap.search_runtime.create_qdrant_connection")
@patch("secval.bootstrap.search_runtime.create_open_search_connection")
@patch("secval.bootstrap.search_runtime.load_search_settings")
def test_create_all_runtime_objects_from_settings(
    mock_load_settings: MagicMock,
    mock_create_open_search: MagicMock,
    mock_create_qdrant: MagicMock,
    mock_create_code_index: MagicMock,
    mock_create_vector_collection: MagicMock,
    mock_embedding_model_class: MagicMock,
    mock_search_service_class: MagicMock,
) -> None:
    settings = SearchSettings(
        open_search=ServiceAddress("open-search-host", 9201),
        qdrant=ServiceAddress("qdrant-host", 6335),
        embedding=EmbeddingSettings(
            provider="local",
            model_name="Qwen/Qwen3-Embedding-0.6B",
            dimension=1024,
            device="cpu",
            max_sequence_length=2048,
        ),
        fusion=FusionSettings(
            candidate_multiplier=4,
            max_candidate_count=80,
        ),
        reranker=RerankerSettings(
            provider="none",
            model_name="BAAI/bge-reranker-base",
            device="cpu",
            candidate_count=10,
            max_sequence_length=256,
            batch_size=8,
        ),
    )
    mock_load_settings.return_value = settings
    open_search = MagicMock()
    qdrant = MagicMock()
    embedding_model = MagicMock()
    search_service = MagicMock()
    mock_create_open_search.return_value = open_search
    mock_create_qdrant.return_value = qdrant
    mock_embedding_model_class.return_value = embedding_model
    mock_search_service_class.return_value = search_service

    runtime = create_search_runtime("custom-search.yaml")

    mock_load_settings.assert_called_once_with("custom-search.yaml")
    mock_create_open_search.assert_called_once_with(
        host="open-search-host",
        port=9201,
    )
    mock_create_qdrant.assert_called_once_with(
        host="qdrant-host",
        port=6335,
    )
    mock_create_code_index.assert_called_once_with(open_search)
    mock_create_vector_collection.assert_called_once_with(qdrant)
    mock_embedding_model_class.assert_called_once_with(
        model_name="Qwen/Qwen3-Embedding-0.6B",
        device="cpu",
        max_sequence_length=2048,
        expected_dimension=1024,
    )
    service_arguments = mock_search_service_class.call_args.kwargs
    assert service_arguments["keyword_retriever"].connection is open_search
    assert service_arguments["vector_retriever"].qdrant_client is qdrant
    assert (
        service_arguments["vector_retriever"].open_search_connection
        is open_search
    )
    assert service_arguments["vector_retriever"].embedding_model is embedding_model
    assert service_arguments["result_fusion"].__class__.__name__ == (
        "RrfResultFusion"
    )
    assert service_arguments["reranker"] is runtime.reranker
    assert service_arguments["candidate_multiplier"] == 4
    assert service_arguments["max_candidate_count"] == 80
    mock_search_service_class.assert_called_once_with(
        keyword_retriever=service_arguments["keyword_retriever"],
        vector_retriever=service_arguments["vector_retriever"],
        result_fusion=service_arguments["result_fusion"],
        reranker=runtime.reranker,
        candidate_multiplier=4,
        max_candidate_count=80,
    )
    assert runtime.settings is settings
    assert runtime.reranker.provider_name == "none"
    assert runtime.search_service is search_service
