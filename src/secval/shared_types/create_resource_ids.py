"""根据资源内容生成稳定的文件、符号和代码块 ID。"""

import hashlib
import json

from secval.shared_types.resource_ids import (
    ChunkId,
    FileId,
    RepositoryId,
    SnapshotId,
    SymbolId,
    require_resource_id,
)


def create_file_id(
    repository_id: RepositoryId,
    snapshot_id: SnapshotId,
    relative_path: str,
) -> FileId:
    """根据仓库、代码版本和文件路径生成稳定的文件 ID。"""

    checked_repository_id = require_resource_id(repository_id, "仓库 ID")
    checked_snapshot_id = require_resource_id(snapshot_id, "代码版本 ID")
    normalized_path = _normalize_relative_path(relative_path)

    values = [checked_repository_id, checked_snapshot_id, normalized_path]
    return FileId(_create_hash_id("file", values))


def create_symbol_id(
    repository_id: RepositoryId,
    snapshot_id: SnapshotId,
    relative_path: str,
    symbol_type: str,
    full_name: str,
    start_line: int,
    start_column: int = 1,
) -> SymbolId:
    """根据符号位置和名称生成稳定的符号 ID。"""

    checked_repository_id = require_resource_id(repository_id, "仓库 ID")
    checked_snapshot_id = require_resource_id(snapshot_id, "代码版本 ID")
    normalized_path = _normalize_relative_path(relative_path)
    checked_symbol_type = _require_text(symbol_type, "符号类型")
    checked_full_name = _require_text(full_name, "符号完整名称")

    if start_line < 1:
        raise ValueError("符号开始行号必须大于或等于 1")

    if start_column < 1:
        raise ValueError("符号开始列号必须大于或等于 1")

    values = [
        checked_repository_id,
        checked_snapshot_id,
        normalized_path,
        checked_symbol_type,
        checked_full_name,
        str(start_line),
        str(start_column),
    ]
    return SymbolId(_create_hash_id("symbol", values))


def create_chunk_id(
    file_id: FileId,
    chunk_type: str,
    start_line: int,
    end_line: int,
    content: str,
    start_column: int = 1,
) -> ChunkId:
    """根据来源文件、精确位置和代码内容生成稳定的代码块 ID。"""

    checked_file_id = require_resource_id(file_id, "文件 ID")
    checked_chunk_type = _require_text(chunk_type, "代码块类型")
    checked_content = _require_text(content, "代码块内容")

    if start_line < 1:
        raise ValueError("代码块开始行号必须大于或等于 1")

    if end_line < start_line:
        raise ValueError("代码块结束行号不能小于开始行号")

    if start_column < 1:
        raise ValueError("代码块开始列号必须大于或等于 1")

    values = [
        checked_file_id,
        checked_chunk_type,
        str(start_line),
        str(end_line),
        str(start_column),
        checked_content,
    ]
    return ChunkId(_create_hash_id("chunk", values))


def _normalize_relative_path(relative_path: str) -> str:
    """清理相对路径，并统一使用正斜杠。"""

    normalized_path = relative_path.strip().replace("\\", "/")

    while normalized_path.startswith("./"):
        normalized_path = normalized_path[2:]

    if not normalized_path:
        raise ValueError("文件相对路径不能为空")

    return normalized_path


def _require_text(value: str, field_name: str) -> str:
    """清理普通文本字段，并拒绝空值。"""

    cleaned_value = value.strip()

    if not cleaned_value:
        raise ValueError(f"{field_name}不能为空")

    return cleaned_value


def _create_hash_id(prefix: str, values: list[str]) -> str:
    """把一组文本转换成带类型前缀的 SHA-256 ID。"""

    serialized_values = json.dumps(
        values,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    hash_value = hashlib.sha256(serialized_values.encode("utf-8")).hexdigest()
    return f"{prefix}_{hash_value}"

