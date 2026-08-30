"""源代码文件的数据模型。"""

from dataclasses import dataclass

from secval.shared_types import FileId, RepositoryId, SnapshotId


@dataclass
class SourceFile:
    """描述从代码仓库中读取到的一份源代码文件。

    file_id 是平台内部使用的文件 ID。
    repository_id 表示文件属于哪个仓库。
    snapshot_id 表示文件属于仓库的哪个版本。
    relative_path 是文件相对于仓库根目录的路径。
    language 是文件使用的编程语言。
    content 是完整的源代码文本。
    """

    file_id: FileId
    repository_id: RepositoryId
    snapshot_id: SnapshotId
    relative_path: str
    language: str
    content: str

    def __post_init__(self) -> None:
        """创建对象时检查定位文件所需的内容。"""

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

