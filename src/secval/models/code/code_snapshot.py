"""代码版本的数据模型。"""

from dataclasses import dataclass

from secval.shared_types import RepositoryId, SnapshotId


@dataclass
class CodeSnapshot:
    """描述代码仓库在某个时间点的版本。

    snapshot_id 是平台内部使用的版本 ID。
    repository_id 表示这个版本属于哪个仓库。
    version 表示 Git commit 或其他可以识别代码版本的值。
    """

    snapshot_id: SnapshotId
    repository_id: RepositoryId
    version: str

    def __post_init__(self) -> None:
        """创建对象时检查必填内容。"""

        if not self.snapshot_id.strip():
            raise ValueError("代码版本 ID 不能为空")

        if not self.repository_id.strip():
            raise ValueError("仓库 ID 不能为空")

        if not self.version.strip():
            raise ValueError("代码版本不能为空")

