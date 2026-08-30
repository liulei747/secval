"""可搜索代码块的数据模型。"""

from dataclasses import dataclass

from secval.shared_types import (
    ChunkId,
    FileId,
    RepositoryId,
    SnapshotId,
    SymbolId,
)


@dataclass
class CodeChunk:
    """描述从源文件中切出的一段代码。

    一个代码块通常对应一个类、方法、函数或一段文件级代码。
    关键词搜索和向量搜索都会使用这里的 content 字段。
    """

    chunk_id: ChunkId
    file_id: FileId
    repository_id: RepositoryId
    snapshot_id: SnapshotId
    relative_path: str
    language: str
    chunk_type: str
    content: str
    start_line: int
    end_line: int
    symbol_id: SymbolId | None = None
    symbol_name: str | None = None

    def __post_init__(self) -> None:
        """创建对象时检查代码块的基本内容和行号。"""

        if not self.chunk_id.strip():
            raise ValueError("代码块 ID 不能为空")

        if not self.file_id.strip():
            raise ValueError("文件 ID 不能为空")

        if not self.repository_id.strip():
            raise ValueError("仓库 ID 不能为空")

        if not self.snapshot_id.strip():
            raise ValueError("代码版本 ID 不能为空")

        if not self.relative_path.strip():
            raise ValueError("文件相对路径不能为空")

        if not self.language.strip():
            raise ValueError("编程语言不能为空")

        if not self.chunk_type.strip():
            raise ValueError("代码块类型不能为空")

        if not self.content.strip():
            raise ValueError("代码块内容不能为空")

        if self.start_line < 1:
            raise ValueError("代码块开始行号必须大于或等于 1")

        if self.end_line < self.start_line:
            raise ValueError("代码块结束行号不能小于开始行号")

