"""代码仓库处理结果的数据模型。"""

from dataclasses import dataclass

from secval.code_processing.code_models.code_chunk import CodeChunk
from secval.code_processing.code_models.file_process_error import FileProcessError


@dataclass
class RepositoryProcessResult:
    """保存一次仓库处理产生的代码块和文件错误。"""

    total_files: int
    successful_files: int
    chunks: list[CodeChunk]
    errors: list[FileProcessError]

    def __post_init__(self) -> None:
        """检查文件数量是否合理。"""

        if self.total_files < 0:
            raise ValueError("扫描文件数量不能小于 0")

        if self.successful_files < 0:
            raise ValueError("成功文件数量不能小于 0")

        if self.successful_files > self.total_files:
            raise ValueError("成功文件数量不能大于扫描文件数量")

        processed_files = self.successful_files + len(self.errors)

        if processed_files != self.total_files:
            raise ValueError("成功文件数量和错误文件数量与扫描总数不一致")
