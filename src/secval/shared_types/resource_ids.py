"""定义 Secval 各板块共同使用的资源 ID。

这些 ID 在程序运行时仍然是字符串，便于保存到数据库或通过 Web 接口传输。
``NewType`` 可以让类型检查工具区分不同 ID，同时不会增加运行开销。
"""

from typing import NewType


RepositoryId = NewType("RepositoryId", str)
"""标识一个已经登记的源代码仓库。"""

SnapshotId = NewType("SnapshotId", str)
"""标识代码仓库的一个版本或一次状态快照。"""

FileId = NewType("FileId", str)
"""标识代码仓库某个版本中的一个源文件。"""

ChunkId = NewType("ChunkId", str)
"""标识一个可以被搜索的代码块。"""

SymbolId = NewType("SymbolId", str)
"""标识类、方法或字段等代码符号。"""


def require_resource_id(value: str, field_name: str) -> str:
    """清理资源 ID 两侧的空格，并拒绝空值。

    这里有意不负责生成 ID。不同资源将在后续使用不同的生成规则。
    """

    cleaned_value = value.strip()
    if not cleaned_value:
        raise ValueError(f"{field_name}不能为空")
    return cleaned_value
