"""读取一份源代码文件并创建 SourceFile。"""

from pathlib import Path

from secval.models.code import SourceFile
from secval.shared_types import FileId, RepositoryId, SnapshotId

# 默认最多读取 2 MiB，避免异常大文件占用过多内存。
DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024

# 文件扩展名和编程语言的对应关系。
FILE_LANGUAGES = {
    ".java": "java",
}


def read_source_file(
    root_path: str,
    relative_path: str,
    file_id: FileId,
    repository_id: RepositoryId,
    snapshot_id: SnapshotId,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> SourceFile:
    """安全读取仓库内的源文件，并返回 SourceFile。"""

    repository_path = Path(root_path)

    if not repository_path.exists():
        raise ValueError(f"仓库根目录不存在：{root_path}")

    if not repository_path.is_dir():
        raise ValueError(f"仓库根路径不是目录：{root_path}")

    if max_file_size < 1:
        raise ValueError("文件大小限制必须大于 0")

    requested_path = Path(relative_path)

    if requested_path.is_absolute():
        raise ValueError("源文件路径必须是仓库内的相对路径")

    repository_path = repository_path.resolve()
    source_path_before_resolve = repository_path / requested_path

    if source_path_before_resolve.is_symlink():
        raise ValueError(f"不读取符号链接文件：{relative_path}")

    source_path = source_path_before_resolve.resolve()

    if not source_path.is_relative_to(repository_path):
        raise ValueError(f"源文件路径超出仓库范围：{relative_path}")

    if not source_path.exists():
        raise ValueError(f"源文件不存在：{relative_path}")

    if not source_path.is_file():
        raise ValueError(f"源文件路径不是文件：{relative_path}")

    language = FILE_LANGUAGES.get(source_path.suffix.lower())

    if language is None:
        raise ValueError(f"暂不支持此文件类型：{relative_path}")

    file_size = source_path.stat().st_size

    if file_size > max_file_size:
        raise ValueError(
            f"源文件超过大小限制：{relative_path}，"
            f"文件大小 {file_size} 字节，限制 {max_file_size} 字节"
        )

    try:
        content = source_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError(f"源文件不是有效的 UTF-8 文本：{relative_path}") from error

    normalized_relative_path = source_path.relative_to(repository_path).as_posix()

    return SourceFile(
        file_id=file_id,
        repository_id=repository_id,
        snapshot_id=snapshot_id,
        relative_path=normalized_relative_path,
        language=language,
        content=content,
    )

