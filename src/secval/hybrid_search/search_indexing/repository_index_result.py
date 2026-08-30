"""代码仓库建立搜索索引后的结果。"""

from dataclasses import dataclass

from secval.code_processing.code_models import RepositoryProcessResult


@dataclass
class RepositoryIndexResult:
    """保存仓库处理情况和 OpenSearch 写入情况。"""

    process_result: RepositoryProcessResult
    deleted_chunks: int
    saved_chunks: int
    saved_vectors: int
    index_created: bool
    vector_collection_created: bool
    index_run_id: str

    def __post_init__(self) -> None:
        """检查写入数量是否合理。"""

        if self.deleted_chunks < 0:
            raise ValueError("删除代码块数量不能小于 0")

        if self.saved_chunks < 0:
            raise ValueError("写入代码块数量不能小于 0")

        if self.saved_vectors < 0:
            raise ValueError("写入向量数量不能小于 0")

        if self.saved_chunks > len(self.process_result.chunks):
            raise ValueError("写入代码块数量不能大于生成的代码块数量")

        if self.saved_vectors > len(self.process_result.chunks):
            raise ValueError("写入向量数量不能大于生成的代码块数量")

        if not self.index_run_id.strip():
            raise ValueError("索引批次 ID 不能为空")
