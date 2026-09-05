"""把源代码文本解析成语法树。"""

from secval.code_processing.source_parsing.java import (
    extract_java_symbols,
    parse_java,
)
from secval.code_processing.source_parsing.python import parse_python

__all__ = ["extract_java_symbols", "parse_java", "parse_python"]
