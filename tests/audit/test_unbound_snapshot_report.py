"""孤立快照报告：只报告不删除，旧快照时间未知单独标注。"""

from pathlib import Path

from secval.infrastructure.audit.source_snapshot_store import SourceSnapshotStore


def _make_store(tmp_path: Path) -> SourceSnapshotStore:
    return SourceSnapshotStore(str(tmp_path / "snapshots.sqlite3"))


def _sample_repository(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    source = root / "Sample.java"
    source.write_text("class Sample {}", encoding="utf-8")
    return root


def test_unbound_snapshot_listed_after_capture(tmp_path):
    store = _make_store(tmp_path)
    source = _sample_repository(tmp_path / "repo")
    snapshot_id = store.capture(source, "repo-a", "v1")
    rows = store.list_unbound_snapshots(older_than_hours=0)
    assert len(rows) == 1
    assert rows[0]["snapshot_id"] == snapshot_id
    assert rows[0]["age_known"] is True
    assert rows[0]["file_count"] >= 1


def test_bound_snapshot_not_reported(tmp_path):
    store = _make_store(tmp_path)
    source = _sample_repository(tmp_path / "repo")
    snapshot_id = store.capture(source, "repo-a", "v1")
    store.bind(snapshot_id, "repo-a", "snap-a", "run-1")
    assert store.list_unbound_snapshots(older_than_hours=0) == []


def test_recent_snapshot_filtered_by_age(tmp_path):
    store = _make_store(tmp_path)
    source = _sample_repository(tmp_path / "repo")
    store.capture(source, "repo-a", "v1")
    # 默认 24 小时内不算孤立；报告为空。
    assert store.list_unbound_snapshots() == []


def test_delete_unbound_snapshot_removes_rows(tmp_path):
    store = _make_store(tmp_path)
    source = _sample_repository(tmp_path / "repo")
    snapshot_id = store.capture(source, "repo-a", "v1")
    removed = store.delete_unbound_snapshot(snapshot_id, older_than_hours=0)
    assert removed >= 1
    assert store.list_unbound_snapshots(older_than_hours=0) == []


def test_delete_bound_snapshot_rejected(tmp_path):
    store = _make_store(tmp_path)
    source = _sample_repository(tmp_path / "repo")
    snapshot_id = store.capture(source, "repo-a", "v1")
    store.bind(snapshot_id, "repo-a", "snap-a", "run-1")
    import pytest
    with pytest.raises(ValueError, match="绑定"):
        store.delete_unbound_snapshot(snapshot_id, older_than_hours=0)


def test_delete_recent_snapshot_rejected(tmp_path):
    store = _make_store(tmp_path)
    source = _sample_repository(tmp_path / "repo")
    snapshot_id = store.capture(source, "repo-a", "v1")
    import pytest
    with pytest.raises(ValueError, match="时限"):
        store.delete_unbound_snapshot(snapshot_id, older_than_hours=24)


def test_delete_missing_snapshot_rejected(tmp_path):
    store = _make_store(tmp_path)
    import pytest
    with pytest.raises(ValueError, match="不存在"):
        store.delete_unbound_snapshot("missing", older_than_hours=0)


def test_iter_captured_files_matches_inventory_order(tmp_path):
    store = _make_store(tmp_path)
    root = tmp_path / "repo"
    root.mkdir()
    for name in ["Alpha.java", "Beta.java"]:
        (root / name).write_text("class " + name.split(".")[0] + " {}",
                                 encoding="utf-8")
    snapshot_id = store.capture(root, "repo-a", "v1")
    pairs = [(path, digest, content) for path, digest, content
             in store.iter_captured_files(snapshot_id, page_size=1)]
    assert [path for path, _, _ in pairs] == ["Alpha.java", "Beta.java"]
    for path, digest, content in pairs:
        import hashlib
        assert hashlib.sha256(content.encode("utf-8")).hexdigest() == digest
