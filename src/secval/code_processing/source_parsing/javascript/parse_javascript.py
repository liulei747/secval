"""使用 Tree-sitter 解析 JavaScript 源代码。"""

import tree_sitter_javascript
from tree_sitter import Language, Parser, Tree

from secval.models.code import SourceFile


JAVASCRIPT_LANGUAGE = Language(tree_sitter_javascript.language())


def parse_javascript(source_file: SourceFile) -> Tree:
    """解析 JavaScript 文件；文件有语法错误时明确拒绝。"""

    if source_file.language.lower() != "javascript":
        raise ValueError(
            f"JavaScript解析器不能处理此编程语言：{source_file.language}"
        )
    syntax_tree = Parser(JAVASCRIPT_LANGUAGE).parse(
        source_file.content.encode("utf-8")
    )
    if syntax_tree.root_node.has_error:
        raise ValueError(f"JavaScript语法解析失败：{source_file.relative_path}")
    return syntax_tree
