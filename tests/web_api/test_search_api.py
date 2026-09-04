from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi.testclient import TestClient

from secval.models.code import CodeChunk
from secval.models.identifiers import (
    ChunkId,
    FileId,
    RepositoryId,
    SnapshotId,
    SymbolId,
)
from secval.models.search import SearchResult
from secval.web_api import create_search_app


def create_zip_file(files: dict[str, bytes]) -> bytes:
    """创建上传接口测试使用的内存 ZIP。"""

    zip_content = BytesIO()
    with ZipFile(zip_content, "w", ZIP_DEFLATED) as archive:
        for relative_path, content in files.items():
            archive.writestr(relative_path, content)
    return zip_content.getvalue()


def create_runtime() -> MagicMock:
    """创建不会加载真实模型和数据库的测试 Runtime。"""

    runtime = MagicMock()
    runtime.open_search_connection.ping.return_value = True
    runtime.qdrant_client.get_collections.return_value = MagicMock()
    runtime.embedding_model.provider_name = "local"
    runtime.embedding_model.model_name = "Qwen/Qwen3-Embedding-0.6B"
    runtime.reranker.provider_name = "none"
    runtime.reranker.model_name = None
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


def test_repository_catalog_returns_all_repository_snapshot_pairs() -> None:
    runtime = create_runtime()
    first_key = {"repository_id": "repo-a", "snapshot_id": "main"}
    second_key = {"repository_id": "repo-a", "snapshot_id": "dev"}
    runtime.open_search_connection.search.side_effect = [
        {"aggregations": {"scopes": {
            "buckets": [{"key": first_key, "doc_count": 4}],
            "after_key": first_key,
        }}},
        {"aggregations": {"scopes": {
            "buckets": [{"key": second_key, "doc_count": 12}],
        }}},
    ]
    with TestClient(create_search_app(runtime)) as client:
        response = client.get("/api/repositories")
    assert response.status_code == 200
    assert response.json()["repositories"] == [
        {**second_key, "chunk_count": 12},
        {**first_key, "chunk_count": 4},
    ]
    calls = runtime.open_search_connection.search.call_args_list
    assert calls[1].kwargs["body"]["aggs"]["scopes"]["composite"]["after"] == first_key
    runtime.embedding_model.embed_query.assert_not_called()


def test_repository_catalog_returns_empty_list_without_indexed_data() -> None:
    runtime = create_runtime()
    runtime.open_search_connection.search.return_value = {
        "aggregations": {"scopes": {"buckets": []}},
    }
    with TestClient(create_search_app(runtime)) as client:
        response = client.get("/api/repositories")
    assert response.status_code == 200
    assert response.json() == {"repositories": []}


def test_repository_catalog_reports_failure_not_empty_list() -> None:
    runtime = create_runtime()
    runtime.open_search_connection.search.return_value = {"timed_out": True}
    with TestClient(create_search_app(runtime)) as client:
        response = client.get("/api/repositories")
    assert response.status_code == 503


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
        "embedding_provider": "local",
        "embedding_model": "Qwen/Qwen3-Embedding-0.6B",
        "vector_collection": "secval-code-vectors-qwen3-06b-v2",
        "reranker_provider": "none",
        "reranker_model": None,
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


def test_upload_repository_saves_relative_file_paths(
    tmp_path,
    monkeypatch,
) -> None:
    """目录上传应保留源码文件在仓库中的相对路径。"""

    monkeypatch.setenv("SECVAL_REPOSITORIES_ROOT", str(tmp_path))
    app = create_search_app(create_runtime())

    with TestClient(app) as client:
        response = client.post(
            "/api/repositories/upload",
            data={"repository_directory": "sample-project"},
            files=[
                (
                    "files",
                    ("src/main/App.java", b"class App {}", "text/plain"),
                ),
                (
                    "files",
                    ("README.md", b"sample", "text/markdown"),
                ),
            ],
        )

    assert response.status_code == 201
    assert response.json() == {
        "repository_path": "sample-project",
        "uploaded_files": 2,
        "uploaded_bytes": 18,
        "replaced_existing": False,
    }
    assert (tmp_path / "sample-project/src/main/App.java").read_bytes() == (
        b"class App {}"
    )
    assert (tmp_path / "sample-project/README.md").read_bytes() == b"sample"


def test_upload_repository_does_not_replace_existing_by_default(
    tmp_path,
    monkeypatch,
) -> None:
    """没有明确允许覆盖时，已有仓库内容必须保持不变。"""

    existing_repository = tmp_path / "sample-project"
    existing_repository.mkdir()
    existing_file = existing_repository / "App.java"
    existing_file.write_text("old code", encoding="utf-8")
    monkeypatch.setenv("SECVAL_REPOSITORIES_ROOT", str(tmp_path))
    app = create_search_app(create_runtime())

    with TestClient(app) as client:
        response = client.post(
            "/api/repositories/upload",
            data={"repository_directory": "sample-project"},
            files=[
                ("files", ("App.java", b"new code", "text/plain")),
            ],
        )

    assert response.status_code == 409
    assert existing_file.read_text(encoding="utf-8") == "old code"


def test_upload_repository_replaces_existing_when_allowed(
    tmp_path,
    monkeypatch,
) -> None:
    """明确允许替换时，新目录应完整取代旧目录。"""

    existing_repository = tmp_path / "sample-project"
    existing_repository.mkdir()
    (existing_repository / "old.java").write_text("old", encoding="utf-8")
    monkeypatch.setenv("SECVAL_REPOSITORIES_ROOT", str(tmp_path))
    app = create_search_app(create_runtime())

    with TestClient(app) as client:
        response = client.post(
            "/api/repositories/upload",
            data={
                "repository_directory": "sample-project",
                "replace_existing": "true",
            },
            files=[
                ("files", ("new.java", b"new", "text/plain")),
            ],
        )

    assert response.status_code == 201
    assert response.json()["replaced_existing"] is True
    assert not (existing_repository / "old.java").exists()
    assert (existing_repository / "new.java").read_bytes() == b"new"


def test_upload_repository_copies_when_directory_rename_is_denied(
    tmp_path,
    monkeypatch,
) -> None:
    """Windows bind mount 拒绝临时目录改名时，应退回逐文件复制。"""

    original_rename = Path.rename

    def deny_temporary_directory_rename(source: Path, target: Path) -> Path:
        if source.name.startswith(".upload-"):
            raise PermissionError("bind mount denied directory rename")
        return original_rename(source, target)

    monkeypatch.setattr(Path, "rename", deny_temporary_directory_rename)
    monkeypatch.setenv("SECVAL_REPOSITORIES_ROOT", str(tmp_path))
    app = create_search_app(create_runtime())

    with TestClient(app) as client:
        response = client.post(
            "/api/repositories/upload",
            data={"repository_directory": "sample-project"},
            files=[
                ("files", ("src/App.java", b"new", "text/plain")),
            ],
        )

    assert response.status_code == 201
    assert (tmp_path / "sample-project/src/App.java").read_bytes() == b"new"


def test_upload_repository_rejects_parent_directory_path(
    tmp_path,
    monkeypatch,
) -> None:
    """文件名中的上级目录不能把文件写出目标仓库。"""

    monkeypatch.setenv("SECVAL_REPOSITORIES_ROOT", str(tmp_path))
    app = create_search_app(create_runtime())

    with TestClient(app) as client:
        response = client.post(
            "/api/repositories/upload",
            data={"repository_directory": "sample-project"},
            files=[
                ("files", ("../outside.java", b"bad", "text/plain")),
            ],
        )

    assert response.status_code == 400
    assert not (tmp_path / "outside.java").exists()
    assert not (tmp_path / "sample-project").exists()


def test_upload_zip_removes_single_outer_directory(
    tmp_path,
    monkeypatch,
) -> None:
    """常见的 project/src 结构应去掉压缩包唯一的 project 外层。"""

    monkeypatch.setenv("SECVAL_REPOSITORIES_ROOT", str(tmp_path))
    app = create_search_app(create_runtime())
    zip_content = create_zip_file(
        {
            "downloaded-project/src/App.java": b"class App {}",
            "downloaded-project/README.md": b"sample",
        }
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/repositories/upload-zip",
            data={"repository_directory": "sample-project"},
            files={"zip_file": ("project.zip", zip_content, "application/zip")},
        )

    assert response.status_code == 201
    assert response.json()["uploaded_files"] == 2
    assert (tmp_path / "sample-project/src/App.java").read_bytes() == (
        b"class App {}"
    )
    assert not (tmp_path / "sample-project/downloaded-project").exists()


def test_upload_zip_rejects_parent_directory_path(
    tmp_path,
    monkeypatch,
) -> None:
    """恶意 ZIP 不能把文件解压到目标仓库外面。"""

    monkeypatch.setenv("SECVAL_REPOSITORIES_ROOT", str(tmp_path))
    app = create_search_app(create_runtime())
    zip_content = create_zip_file({"../../outside.java": b"bad"})

    with TestClient(app) as client:
        response = client.post(
            "/api/repositories/upload-zip",
            data={"repository_directory": "sample-project"},
            files={"zip_file": ("project.zip", zip_content, "application/zip")},
        )

    assert response.status_code == 400
    assert not (tmp_path / "outside.java").exists()
    assert not (tmp_path / "sample-project").exists()


def test_upload_zip_rejects_non_zip_file(
    tmp_path,
    monkeypatch,
) -> None:
    """只有扩展名正确且内容有效的 ZIP 才能进入解压流程。"""

    monkeypatch.setenv("SECVAL_REPOSITORIES_ROOT", str(tmp_path))
    app = create_search_app(create_runtime())

    with TestClient(app) as client:
        response = client.post(
            "/api/repositories/upload-zip",
            data={"repository_directory": "sample-project"},
            files={"zip_file": ("project.zip", b"not a zip", "application/zip")},
        )

    assert response.status_code == 400
    assert not (tmp_path / "sample-project").exists()
