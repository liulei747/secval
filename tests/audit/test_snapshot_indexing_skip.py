"""采集策略排除的受支持源文件不阻塞索引还原。"""

from pathlib import Path

from secval.infrastructure.audit.source_snapshot_store import SourceSnapshotStore


def test_indexing_directory_skips_policy_excluded_files(tmp_path: Path):
    store = SourceSnapshotStore(str(tmp_path / "sources.sqlite3"))
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.java").write_text("class App {}", encoding="utf-8")
    big = repo / "static.js"
    big.write_bytes(b"var x=1;" * 200000)  # >1MB, 触发 file_too_large
    snapshot_id = store.capture(repo, "demo", "v1")

    with store.indexing_directory(snapshot_id) as root:
        restored = {p.relative_to(root).as_posix() for p in Path(root).rglob("*") if p.is_file()}

    assert restored == {"src/app.java"}
