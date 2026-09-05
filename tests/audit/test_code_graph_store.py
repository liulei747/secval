"""Neo4j 关系存储只接收当前索引批次，并去重文件和符号。"""

from unittest.mock import MagicMock

from secval.infrastructure.neo4j import CodeGraphStore
from secval.models.code import CodeChunk
from secval.models.identifiers import ChunkId, FileId, RepositoryId, SnapshotId, SymbolId


def test_save_snapshot_deduplicates_file_and_symbol():
    driver = MagicMock()
    store = CodeGraphStore(driver)
    chunk = CodeChunk(
        ChunkId("chunk-1"), FileId("file-1"), RepositoryId("repo"), SnapshotId("snap"),
        "src/Order.java", "java", "method", "void run() {}", 3, 3,
        symbol_ids=[SymbolId("symbol-1")], symbol_names=["Order.run"],
    )

    result = store.save_snapshot("repo", "snap", "run-1", [chunk, chunk])

    assert result == {"files": 1, "symbols": 1}
    arguments = driver.execute_query.call_args.kwargs
    assert "WITH DISTINCT s" in driver.execute_query.call_args.args[0]
    assert arguments["snapshot_key"] == "repo:snap:run-1"
    assert arguments["files"] == [{"id": "file-1", "path": "src/Order.java"}]
    assert arguments["symbols"][0]["name"] == "Order.run"


def test_find_symbol_is_bound_to_repository_snapshot_and_run():
    driver = MagicMock()
    driver.execute_query.return_value = ([{"name": "Order.run", "path": "src/Order.java"}], None, None)

    rows = CodeGraphStore(driver).find_symbol("repo", "snap", "run-1", "Order", 5)

    assert rows[0]["name"] == "Order.run"
    arguments = driver.execute_query.call_args.kwargs
    assert arguments["repository_id"] == "repo"
    assert arguments["snapshot_id"] == "snap"
    assert arguments["index_run_id"] == "run-1"
    assert "snapshot_id_id" not in arguments
