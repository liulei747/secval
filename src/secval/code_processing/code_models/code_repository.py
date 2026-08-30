"""代码仓库的数据模型。"""

from dataclasses import dataclass

from secval.shared_types import RepositoryId


@dataclass
class CodeRepository:
    """描述一个等待扫描和建立索引的代码仓库。

    repository_id 是平台内部使用的仓库 ID。
    name 是展示给用户看的仓库名称。
    root_path 是仓库在当前机器上的根目录。
    """

    repository_id: RepositoryId
    name: str
    root_path: str

    def __post_init__(self) -> None:
        """创建对象时检查必填内容。"""

        if not self.repository_id.strip():
            raise ValueError("仓库 ID 不能为空")

        if not self.name.strip():
            raise ValueError("仓库名称不能为空")

        if not self.root_path.strip():
            raise ValueError("仓库根目录不能为空")

