"""读取配置并组装应用运行对象。"""

from .search_runtime import SearchRuntime, create_search_runtime

__all__ = ["SearchRuntime", "create_search_runtime"]
