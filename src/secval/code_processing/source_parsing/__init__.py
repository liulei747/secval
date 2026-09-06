"""把源代码文本解析成语法树。"""

from secval.code_processing.source_parsing.java import (
    extract_java_symbols,
    parse_java,
)
from secval.code_processing.source_parsing.javascript import parse_javascript
from secval.code_processing.source_parsing.python import parse_python
from secval.code_processing.source_parsing.typescript import parse_typescript

__all__ = [
    "extract_java_symbols",
    "parse_java",
    "parse_javascript",
    "parse_python",
    "parse_typescript",
]
