"""本地源码快照底座；正文由取证工具授权，不推断仓库 ID 与磁盘目录的关系。"""

import hashlib
import os
import sqlite3
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
                    repository_id TEXT NOT NULL, snapshot_id TEXT NOT NULL
                );
            """)

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

        def refuse_scan_error(error):
            # os.walk 默认跳过无法扫描的目录，会把不完整清单误当成功快照。
            raise ValueError("源码目录扫描失败，快照未保存；请检查目录权限或并发变更") from None

        with self._connect() as db:
            db.execute("INSERT INTO source_snapshots VALUES (?, ?, ?)",
                       (snapshot_id, repository_id, version_label))
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
            for relative, status in rows:
                if not is_supported_source(relative):
                    continue
                if status != "captured":
                    raise ValueError("存在未采集的受支持源文件，不能建立完整代码索引")
                destination = (root / relative).resolve()
                if not destination.is_relative_to(root):
                    raise ValueError("快照路径越界")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(self.read(snapshot_id, relative).encode("utf-8"))
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
        """只在双存储写入及旧批次清理成功之后登记，不覆盖已有批次。"""
        with self._connect() as db:
            row = db.execute("SELECT repository_id FROM source_snapshots WHERE id=?",
                             (source_snapshot_id,)).fetchone()
            if row is None or row[0] != repository_id:
                raise ValueError("源码快照不属于当前仓库")
            db.execute("INSERT INTO source_index_bindings VALUES (?, ?, ?, ?)",
                       (index_run_id, source_snapshot_id, repository_id, snapshot_id))

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
        """列出旧分析批次，只用于新批次完成后的延迟清理。"""
        with self._connect() as db:
            rows = db.execute(
                "SELECT index_run_id FROM source_index_bindings "
                "WHERE repository_id=? AND snapshot_id=? ORDER BY index_run_id",
                (repository_id, snapshot_id),
            ).fetchall()
        return [row[0] for row in rows]

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
