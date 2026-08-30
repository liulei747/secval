"""搜索结果的数据模型。"""

from dataclasses import dataclass

from secval.code_processing.code_models import CodeChunk


@dataclass
class SearchResult:
    """描述一个已经完成排名的代码搜索结果。

    keyword_score 和 vector_score 分别保存两路原始分数。
    某一路没有找到这个代码块时，对应分数可以为 None。
    """

    chunk: CodeChunk
    rank: int
    final_score: float
    keyword_score: float | None = None
    vector_score: float | None = None

    def __post_init__(self) -> None:
        """创建结果时检查排名和分数来源。"""

        if self.rank < 1:
            raise ValueError("搜索结果排名必须大于或等于 1")

        if self.keyword_score is None and self.vector_score is None:
            raise ValueError("搜索结果至少需要一个关键词或向量分数")

