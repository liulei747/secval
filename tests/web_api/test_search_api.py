from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from secval.code_processing.code_models import CodeChunk
from secval.hybrid_search.search_models import SearchResult
from secval.shared_types import (
    ChunkId,
    FileId,
    RepositoryId,
    SnapshotId,
    SymbolId,
)
from secval.web_api import create_search_app


def create_runtime() -> MagicMock:
    """创建不会加载真实模型和数据库的测试 Runtime。"""

    runtime = MagicMock()
    runtime.open_search_connection.ping.return_value = True
    runtime.qdrant_client.get_collections.return_value = MagicMock()
    return runtime


def create_search_result() -> SearchResult:
    """创建 Web 响应转换测试使用的搜索结果。"""

    chunk = CodeChunk(
        chunk_id=ChunkId("chunk-1"),
        file_id=FileId("file-1"),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        relative_path="src/UserService.java",
        language="java",
        chunk_type="method",
        content="void findUser() {}",
        start_line=10,
        end_line=10,
        symbol_id=SymbolId("symbol-1"),
        symbol_name="UserService.findUser()",
    )
    return SearchResult(
        chunk=chunk,
        rank=1,
        final_score=0.03,
        keyword_score=4.2,
        vector_score=0.8,
    )


def test_health_endpoint_reports_both_stores() -> None:
    runtime = create_runtime()
    app = create_search_app(runtime)

    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "open_search": "available",
        "qdrant": "available",
    }


def test_health_endpoint_returns_503_when_qdrant_is_unavailable() -> None:
    runtime = create_runtime()
    runtime.qdrant_client.get_collections.side_effect = RuntimeError(
        "cannot connect"
    )
    app = create_search_app(runtime)

    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 503
    assert response.json()["status"] == "unhealthy"
    assert response.json()["qdrant"] == "unavailable"


def test_search_endpoint_returns_code_results() -> None:
    runtime = create_runtime()
    runtime.search_service.search.return_value = [create_search_result()]
    app = create_search_app(runtime)
    request_body = {
        "text": "find user",
        "repository_ids": ["repository-1"],
        "snapshot_ids": ["snapshot-1"],
        "top_k": 5,
        "language": "java",
        "path_prefix": "src/",
        "chunk_type": "method",
    }

    with TestClient(app) as client:
        response = client.post("/api/search", json=request_body)

    assert response.status_code == 200
    body = response.json()
    assert body["result_count"] == 1
    assert body["results"][0]["chunk_id"] == "chunk-1"
    assert body["results"][0]["symbol_name"] == (
        "UserService.findUser()"
    )
    assert body["results"][0]["symbol_ids"] == ["symbol-1"]
    assert body["results"][0]["symbol_names"] == [
        "UserService.findUser()"
    ]
    assert body["results"][0]["keyword_score"] == 4.2
    assert body["results"][0]["vector_score"] == 0.8

    query = runtime.search_service.search.call_args.args[0]
    assert query.text == "find user"
    assert query.repository_ids == ["repository-1"]
    assert query.top_k == 5


def test_search_endpoint_rejects_invalid_top_k() -> None:
    runtime = create_runtime()
    app = create_search_app(runtime)

    with TestClient(app) as client:
        response = client.post(
            "/api/search",
            json={
                "text": "find user",
                "repository_ids": ["repository-1"],
                "snapshot_ids": ["snapshot-1"],
                "top_k": 0,
            },
        )

    assert response.status_code == 422
    runtime.search_service.search.assert_not_called()
