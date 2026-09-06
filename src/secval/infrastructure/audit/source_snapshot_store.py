"""本地源码快照底座；正文由取证工具授权，不推断仓库 ID 与磁盘目录的关系。"""

import hashlib
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from secval.code_processing.repository_scan import is_supported_source, language_for_source


class SourceSnapshotStore:
    """事务保存有限文本文件及排除清单，之后只读取保存的副本。"""

    def __init__(self, database: str):
        Path(database).parent.mkdir(parents=True, exist_ok=True)
        self.database = database
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS source_snapshots (
                    id TEXT PRIMARY KEY, repository_id TEXT, version_label TEXT
                );
                CREATE TABLE IF NOT EXISTS source_files (
                    snapshot_id TEXT, path TEXT, status TEXT, digest TEXT, content TEXT,
                    PRIMARY KEY(snapshot_id, path)
                );
                CREATE TABLE IF NOT EXISTS source_index_bindings (
                    index_run_id TEXT PRIMARY KEY, source_snapshot_id TEXT NOT NULL,
                    repository_id TEXT NOT NULL, snapshot_id TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                );
            """)
            columns = {
                row[1] for row in db.execute(
                    "PRAGMA table_info(source_index_bindings)"
                ).fetchall()
            }
            if "active" not in columns:
                db.execute(
                    "ALTER TABLE source_index_bindings "
                    "ADD COLUMN active INTEGER NOT NULL DEFAULT 1"
                )
            snapshot_columns = {
                row[1] for row in db.execute(
                    "PRAGMA table_info(source_snapshots)").fetchall()
            }
            if "captured_at" not in snapshot_columns:
                db.execute(
                    "ALTER TABLE source_snapshots ADD COLUMN captured_at REAL"
                )

    @contextmanager
    def _connect(self):
        """既处理事务，也释放句柄，避免Windows文件占用及长期连接积累。"""
        connection = sqlite3.connect(self.database)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def capture(self, root: Path, repository_id: str, version_label: str) -> str:
        """显式指定来源；有界采集，不声称整个目录在同一时刻原子冻结。"""
        if not repository_id.strip() or not version_label.strip():
            raise ValueError("仓库和版本标签不能为空")
        root = Path(root)
        if root.is_symlink() or not root.is_dir():
            raise ValueError("来源必须是普通目录")
        root = root.resolve()
        snapshot_id = uuid4().hex
        total_bytes = 0
        count = 0
        captured_at = time.time()

        def refuse_scan_error(error):
            # os.walk 默认跳过无法扫描的目录，会把不完整清单误当成功快照。
            raise ValueError("源码目录扫描失败，快照未保存；请检查目录权限或并发变更") from None

        with self._connect() as db:
            db.execute(
                "INSERT INTO source_snapshots (id, repository_id, version_label, captured_at) "
                "VALUES (?, ?, ?, ?)",
                (snapshot_id, repository_id, version_label, captured_at),
            )
            for folder, directories, files in os.walk(root, followlinks=False, onerror=refuse_scan_error):
                for name in sorted(directories + files):
                    count += 1
                    if count > 10000:
                        raise ValueError("源码清单超过 10000 项，快照未保存")
                    path = Path(folder) / name
                    relative = path.relative_to(root).as_posix()
                    status = self._excluded(path, root)
                    content = None
                    digest = None
                    if path.is_dir() and status is None:
                        continue
                    if status is not None and name in directories:
                        directories.remove(name)
                    if status is None:
                        before = path.stat()
                        if before.st_size > 1024 * 1024:
                            status = "file_too_large"
                        else:
                            with path.open("rb") as source:
                                raw = source.read(1024 * 1024 + 1)
                            after = path.stat()
                            if (before.st_mtime_ns, before.st_size) != (
                                after.st_mtime_ns, after.st_size
                            ) or len(raw) != before.st_size:
                                raise ValueError("采集期间文件发生变化，快照未保存")
                            total_bytes += len(raw)
                            if total_bytes > 50 * 1024 * 1024:
                                raise ValueError("源码快照超过 50 MB，快照未保存")
                            try:
                                content = raw.decode("utf-8")
                            except UnicodeDecodeError:
                                status = "non_utf8"
                            else:
                                if "\x00" in content:
                                    content = None
                                    status = "binary"
                                else:
                                    digest = hashlib.sha256(raw).hexdigest()
                                    status = "captured"
                    db.execute("INSERT INTO source_files VALUES (?, ?, ?, ?, ?)",
                               (snapshot_id, relative, status, digest, content))
        return snapshot_id

    @contextmanager
    def indexing_directory(self, snapshot_id: str):
        """将固定副本中已支持的源文件还原到私有临时目录。"""
        with self._connect() as db:
            rows = db.execute(
                "SELECT path, status FROM source_files WHERE snapshot_id=?",
                (snapshot_id,),
            ).fetchall()
        with TemporaryDirectory(prefix="secval-index-") as directory:
            root = Path(directory).resolve()
            skipped: list[str] = []
            for relative, status in rows:
                if not is_supported_source(relative):
                    continue
                if status != "captured":
                    # 采集策略主动排除的文件（超大、非UTF-8）与其他排除项同对待：
                    # 不进入还原目录，也就不会参与扫描与索引；不视为完整性破坏。
                    skipped.append(relative)
                    continue
                destination = (root / relative).resolve()
                if not destination.is_relative_to(root):
                    raise ValueError("快照路径越界")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(self.read(snapshot_id, relative).encode("utf-8"))
            if skipped:
                logging.getLogger(__name__).warning(
                    "索引还原跳过 %d 个采集策略排除的受支持源文件，例如：%s",
                    len(skipped), ", ".join(skipped[:5]),
                )
            yield str(root)

    @contextmanager
    def joern_directory(self, snapshot_id: str, shared_root: str, language: str | None = None):
        """按语言把固定快照还原到API与Joern共享的私有目录。"""
        base = Path(shared_root).resolve()
        base.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            rows = db.execute(
                "SELECT path, status FROM source_files WHERE snapshot_id=? ORDER BY path",
                (snapshot_id,),
            ).fetchall()
        with TemporaryDirectory(prefix="secval-joern-", dir=base) as directory:
            root = Path(directory).resolve()
            if not root.is_relative_to(base):
                raise ValueError("Joern临时目录越界")
            for relative, status in rows:
                if not is_supported_source(relative):
                    continue
                if language is not None and language_for_source(relative) != language:
                    continue
                if status != "captured":
                    raise ValueError("存在未采集的受支持源文件，不能建立Joern分析图")
                destination = (root / relative).resolve()
                if not destination.is_relative_to(root):
                    raise ValueError("Joern快照路径越界")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(self.read(snapshot_id, relative), encoding="utf-8")
            yield root.as_posix()

    def bind(self, source_snapshot_id: str, repository_id: str,
             snapshot_id: str, index_run_id: str) -> None:
        """只在本批次全部新数据写入成功后登记，不覆盖已有批次。"""
        with self._connect() as db:
            row = db.execute("SELECT repository_id FROM source_snapshots WHERE id=?",
                             (source_snapshot_id,)).fetchone()
            if row is None or row[0] != repository_id:
                raise ValueError("源码快照不属于当前仓库")
            db.execute(
                "INSERT INTO source_index_bindings "
                "(index_run_id, source_snapshot_id, repository_id, snapshot_id, active) "
                "VALUES (?, ?, ?, ?, 1)",
                (index_run_id, source_snapshot_id, repository_id, snapshot_id),
            )

    def delete_unbound_snapshot(self, snapshot_id: str,
                                older_than_hours: float = 24) -> int:
        """删除从未绑定任何索引批次且超过时限的快照，返回删除文件数。

    二次校验：绑定关系在任何时刻出现即拒绝，不依赖调用方先查报告。
    历史绑定的快照（即使已停用）永久保留，供历史审计取证。
    """
        cutoff = time.time() - older_than_hours * 3600
        with self._connect() as db:
            row = db.execute(
                "SELECT captured_at FROM source_snapshots WHERE id=?",
                (snapshot_id,),
            ).fetchone()
            if row is None:
                raise ValueError("快照不存在")
            captured_at = row[0]
            if not isinstance(captured_at, (int, float)) or captured_at <= 0:
                raise ValueError("旧快照缺少采集时间，无法确认安全删除；请人工核对")
            if captured_at >= cutoff:
                raise ValueError("快照未超过保留时限")
            bound = db.execute(
                "SELECT COUNT(*) FROM source_index_bindings "
                "WHERE source_snapshot_id=?",
                (snapshot_id,),
            ).fetchone()[0]
            if bound:
                raise ValueError("快照已绑定索引批次，不允许删除")
            cursor = db.execute("DELETE FROM source_files WHERE snapshot_id=?",
                                (snapshot_id,))
            db.execute("DELETE FROM source_snapshots WHERE id=?", (snapshot_id,))
            return cursor.rowcount

    def resolve_binding(self, repository_id: str, snapshot_id: str,
                        index_run_id: str) -> str | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT source_snapshot_id FROM source_index_bindings "
                "WHERE repository_id=? AND snapshot_id=? AND index_run_id=?",
                (repository_id, snapshot_id, index_run_id),
            ).fetchone()
        return row[0] if row else None

    def list_bound_runs(self, repository_id: str, snapshot_id: str) -> list[str]:
        """列出仍作为当前结果使用的分析批次。"""
        with self._connect() as db:
            rows = db.execute(
                "SELECT index_run_id FROM source_index_bindings "
                "WHERE repository_id=? AND snapshot_id=? AND active=1 "
                "ORDER BY index_run_id",
                (repository_id, snapshot_id),
            ).fetchall()
        return [row[0] for row in rows]

    def retire_old_bindings(self, repository_id: str, snapshot_id: str,
                            current_index_run_id: str) -> int:
        """新批次完成清理后停用旧批次，但保留历史源码取证关系。"""

        with self._connect() as db:
            cursor = db.execute(
                "UPDATE source_index_bindings SET active=0 "
                "WHERE repository_id=? AND snapshot_id=? "
                "AND index_run_id<>? AND active=1",
                (repository_id, snapshot_id, current_index_run_id),
            )
        return cursor.rowcount

    def list_unbound_snapshots(self, older_than_hours: float = 24):
        """列出保存后从未绑定索引批次的快照，按采集时间分层。

    旧快照没有 captured_at（迁移前保存），单独列为 unknown_age 供人工判断；
    只报告不删除：清理必须人工确认，不能违反“不提前删除旧索引”原则。
    """
        cutoff = time.time() - older_than_hours * 3600
        with self._connect() as db:
            columns = {row[1] for row in db.execute(
                "PRAGMA table_info(source_snapshots)").fetchall()
            }
            if "captured_at" not in columns:
                return []
            rows = db.execute(
                "SELECT s.id, s.repository_id, s.version_label, s.captured_at, "
                "(SELECT COUNT(*) FROM source_files f WHERE f.snapshot_id = s.id) "
                "FROM source_snapshots s "
                "WHERE NOT EXISTS (SELECT 1 FROM source_index_bindings b "
                "WHERE b.source_snapshot_id = s.id) "
                "ORDER BY s.rowid"
            ).fetchall()
        result = []
        for snapshot_id, repository_id, version_label, captured_at, file_count in rows:
            known_age = isinstance(captured_at, (int, float)) and captured_at > 0
            if known_age and captured_at >= cutoff:
                continue
            result.append({"snapshot_id": snapshot_id, "repository_id": repository_id,
                           "version_label": version_label, "file_count": file_count,
                           "age_known": known_age,
                           "captured_at": captured_at if known_age else None})
        return result

    @staticmethod
    def _excluded(path: Path, root: Path) -> str | None:
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            return "link_or_outside_root"
        name = path.name.lower()
        if name.startswith(".env") or name in {
            ".git", ".ssh", "credentials", "id_rsa", "id_ed25519",
        } or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".jks"}:
            return "sensitive_name"
        if path.is_dir() and name in {"node_modules", ".venv", "__pycache__", "target"}:
            return "generated_directory"
        if not path.is_dir() and not path.is_file():
            return "special_file"
        return None

    def inventory(self, snapshot_id: str, offset: int = 0) -> list[dict]:
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("清单偏移必须为非负整数")
        with self._connect() as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(
                "SELECT path, status, digest FROM source_files "
                "WHERE snapshot_id=? ORDER BY path LIMIT 100 OFFSET ?",
                (snapshot_id, offset),
            )]

    def read(self, snapshot_id: str, path: str) -> str:
        """仅查询快照表，不使用模型提供的路径访问文件系统。"""
        with self._connect() as db:
            row = db.execute(
                "SELECT status, digest, content FROM source_files "
                "WHERE snapshot_id=? AND path=?", (snapshot_id, path),
            ).fetchone()
        if row is None or row[0] != "captured":
            raise ValueError("文件未包含在可读快照中")
        if hashlib.sha256(row[2].encode("utf-8")).hexdigest() != row[1]:
            raise ValueError("快照内容校验失败")
        return row[2]

    def iter_captured_files(self, snapshot_id: str, page_size: int = 100):
        """按路径序分页产出（path, digest, content），供字面搜索单次遍历。

        行为与 inventory+read 等价但省去每文件二次查询。
        """
        with self._connect() as db:
            offset = 0
            while True:
                rows = db.execute(
                    "SELECT path, status, digest, content FROM source_files "
                    "WHERE snapshot_id=? AND status='captured' "
                    "ORDER BY path LIMIT ? OFFSET ?",
                    (snapshot_id, page_size, offset),
                ).fetchall()
                if not rows:
                    return
                for row in rows:
                    yield row[0], row[2], row[3]
                if len(rows) < page_size:
                    return
                offset += page_size
