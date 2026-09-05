"""事务结束必须关闭连接，同时保留失败回滚语义。"""

import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from secval.infrastructure.audit.source_snapshot_store import SourceSnapshotStore
from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.infrastructure.audit.index_evidence_tools import EvidenceTools


@pytest.mark.parametrize("store_type", [SourceSnapshotStore, AuditStore])
def test_connection_is_closed_after_operations(tmp_path, store_type):
    real_connect = sqlite3.connect
    connections = []

    def connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        connections.append(connection)
        return connection

    with patch("sqlite3.connect", side_effect=connect):
        store = store_type(str(tmp_path / "test.sqlite3"))
        if store_type is SourceSnapshotStore:
            root = tmp_path / "repo"
            root.mkdir()
            source = b"class Test {\r\n}\r\n"
            (root / "Test.java").write_bytes(source)
            source_id = store.capture(root, "repo", "snap")
            assert store.read(source_id, "Test.java").encode() == source
            store.bind(source_id, "repo", "snap", "run")
            assert store.resolve_binding("repo", "snap", "run") == source_id
            assert len(store.inventory(source_id)) == 1
            with store.indexing_directory(source_id) as directory:
                from pathlib import Path
                assert (Path(directory) / "Test.java").read_bytes() == source
        else:
            task = store.create({"objective": "test"})
            store.update(task["id"], status="failed")
            assert store.get(task["id"])["status"] == "failed"
            assert len(store.list()) == 1
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_source_transaction_rolls_back(tmp_path):
    store = SourceSnapshotStore(str(tmp_path / "test.sqlite3"))
    with pytest.raises(RuntimeError):
        with store._connect() as db:
            db.execute("INSERT INTO source_snapshots VALUES ('test', 'repo', 'snap')")
            raise RuntimeError("abort")
    with store._connect() as db:
        assert db.execute("SELECT count(*) FROM source_snapshots").fetchone()[0] == 0


def test_python_source_is_restored_and_available_as_audit_evidence(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "service.py").write_text("def ready():\n    return True\n", encoding="utf-8")
    (root / "Ready.java").write_text("class Ready {}\n", encoding="utf-8")
    (root / "notes.txt").write_text("不是授权源码", encoding="utf-8")
    store = SourceSnapshotStore(str(tmp_path / "source.sqlite3"))
    source_id = store.capture(root, "repo", "version")
    store.bind(source_id, "repo", "snap", "run-1")

    with store.indexing_directory(source_id) as directory:
        from pathlib import Path
        assert (Path(directory) / "service.py").is_file()
        assert (Path(directory) / "Ready.java").is_file()
        assert not (Path(directory) / "notes.txt").exists()

    shared = tmp_path / "joern-inputs"
    with store.joern_directory(source_id, str(shared), "python") as directory:
        from pathlib import Path
        assert (Path(directory) / "service.py").is_file()
        assert not (Path(directory) / "Ready.java").exists()
    with store.joern_directory(source_id, str(shared), "java") as directory:
        from pathlib import Path
        assert (Path(directory) / "Ready.java").is_file()
        assert not (Path(directory) / "service.py").exists()

    connection = MagicMock()
    connection.transport.perform_request.return_value = {"pit_id": "fixed-view"}
    connection.search.return_value = {
        "timed_out": False, "_shards": {"failed": 0},
        "aggregations": {"runs": {"buckets": [{"key": "run-1"}]},
                         "missing_run": {"doc_count": 0}},
    }
    tools = EvidenceTools(connection, "repo", "snap", store)
    result = tools.call("read_file", {"path": "service.py"})

    assert result["rows"][0]["relative_path"] == "service.py"
    assert "def ready" in result["rows"][0]["content"]
    with pytest.raises(ValueError, match="已支持源码"):
        tools.call("read_file", {"path": "notes.txt"})
