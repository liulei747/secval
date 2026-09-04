"""在请求OpenSearch前检查查询中是否存在可搜索内容。"""

import re

SEARCHABLE_CHARACTER_PATTERN = re.compile(r"[A-Za-z0-9\u4e00-\u9fff]")


def require_searchable_text(text: str) -> None:
    """拒绝只包含空白或标点的查询；正式分词由OpenSearch analyzer完成。"""

    if SEARCHABLE_CHARACTER_PATTERN.search(text) is None:
        raise ValueError("搜索文本不包含可以搜索的文字或数字")
