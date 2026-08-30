"""供 Secval Web 客户端和其他服务使用的 HTTP 接口。"""
"""Secval 的 Web API。"""

from .search_api import app, create_search_app

__all__ = ["app", "create_search_app"]
