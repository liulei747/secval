"""搜索请求的数据模型。"""

from dataclasses import dataclass

from secval.shared_types import RepositoryId, SnapshotId


@dataclass
class SearchQuery:
    """描述一次代码搜索请求。

    repository_ids 和 snapshot_ids 限定允许搜索的数据范围。
    language、path_prefix 和 chunk_type 是可选过滤条件。
    """

    text: str
    repository_ids: list[RepositoryId]
    snapshot_ids: list[SnapshotId]
    top_k: int = 10
    language: str | None = None
    path_prefix: str | None = None
    chunk_type: str | None = None

    def __post_init__(self) -> None:
        """创建查询时检查必填内容和返回数量。"""

        if not self.text.strip():
            raise ValueError("搜索文本不能为空")

        if len(self.repository_ids) == 0:
            raise ValueError("至少需要指定一个仓库 ID")

        if len(self.snapshot_ids) == 0:
            raise ValueError("至少需要指定一个代码版本 ID")

        for repository_id in self.repository_ids:
            if not repository_id.strip():
                raise ValueError("仓库 ID 不能为空")

        for snapshot_id in self.snapshot_ids:
            if not snapshot_id.strip():
                raise ValueError("代码版本 ID 不能为空")

        if self.top_k < 1:
            raise ValueError("搜索结果数量必须大于或等于 1")

        if self.top_k > 100:
            raise ValueError("搜索结果数量不能大于 100")

        if self.language is not None and not self.language.strip():
            raise ValueError("编程语言过滤条件不能为空字符串")

        if self.path_prefix is not None and not self.path_prefix.strip():
            raise ValueError("文件路径过滤条件不能为空字符串")

        if self.chunk_type is not None and not self.chunk_type.strip():
            raise ValueError("代码块类型过滤条件不能为空字符串")

