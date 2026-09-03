"""向量召回能力接口。"""

from typing import Protocol

from secval.models.search import SearchQuery, SearchResult


class VectorRetriever(Protocol):
    """搜索服务只依赖此能力，不关心底层向量数据库。"""

    def search(self, query: SearchQuery) -> list[SearchResult]: ...
