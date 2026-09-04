"""代码符号的数据模型。"""

from dataclasses import dataclass

from secval.models.identifiers import (
    FileId,
    RepositoryId,
    SnapshotId,
    SymbolId,
)


@dataclass
class CodeSymbol:
    """描述源代码中的一个类、方法、字段或其他符号。

    symbol_type 表示符号类型，例如 class、method 或 field。
    name 是代码中直接出现的短名称。
    full_name 是包含包名和所属类型的完整名称。
    parent_symbol_id 表示这个符号直接属于哪个上级符号。
    """

    symbol_id: SymbolId
    file_id: FileId
    repository_id: RepositoryId
    snapshot_id: SnapshotId
    symbol_type: str
    name: str
    full_name: str
    start_line: int
    end_line: int
    parent_symbol_id: SymbolId | None = None

    def __post_init__(self) -> None:
        """创建对象时检查符号的基本内容和行号。"""

        if not self.symbol_id.strip():
            raise ValueError("符号 ID 不能为空")

        if not self.file_id.strip():
            raise ValueError("文件 ID 不能为空")

        if not self.repository_id.strip():
            raise ValueError("仓库 ID 不能为空")

        if not self.snapshot_id.strip():
            raise ValueError("代码版本 ID 不能为空")

        if not self.symbol_type.strip():
            raise ValueError("符号类型不能为空")

        if not self.name.strip():
            raise ValueError("符号名称不能为空")

        if not self.full_name.strip():
            raise ValueError("符号完整名称不能为空")

        if self.start_line < 1:
            raise ValueError("符号开始行号必须大于或等于 1")

        if self.end_line < self.start_line:
            raise ValueError("符号结束行号不能小于开始行号")

        if (
            self.parent_symbol_id is not None
            and not self.parent_symbol_id.strip()
        ):
            raise ValueError("上级符号 ID 不能为空字符串")

