"""组织代码搜索索引的建立流程。"""

from .index_repository import index_repository
from .repository_index_result import RepositoryIndexResult

__all__ = ["RepositoryIndexResult", "index_repository"]
