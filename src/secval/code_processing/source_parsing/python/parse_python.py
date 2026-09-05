"""使用 Tree-sitter 解析 Python 源码。"""

import tree_sitter_python
from tree_sitter import Language, Parser, Tree

from secval.models.code import SourceFile

PYTHON_LANGUAGE = Language(tree_sitter_python.language())


def parse_python(source_file: SourceFile) -> Tree:
    if source_file.language.lower() != "python":
        raise ValueError(f"Python解析器不能处理此编程语言：{source_file.language}")

    syntax_tree = Parser(PYTHON_LANGUAGE).parse(source_file.content.encode("utf-8"))
    if syntax_tree.root_node.has_error:
        raise ValueError(f"Python语法解析失败：{source_file.relative_path}")
    return syntax_tree
