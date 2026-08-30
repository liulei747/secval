"""使用 Tree-sitter 解析 Java 源代码。"""

import tree_sitter_java
from tree_sitter import Language, Parser, Tree

from secval.code_processing.code_models import SourceFile


# Java 语法定义在程序运行期间不会变化，可以安全地重复使用。
JAVA_LANGUAGE = Language(tree_sitter_java.language())


def parse_java(source_file: SourceFile) -> Tree:
    """解析 Java 文件并返回 Tree-sitter 语法树。"""

    if source_file.language.lower() != "java":
        raise ValueError(
            f"Java 解析器不能处理此编程语言：{source_file.language}"
        )

    source_bytes = source_file.content.encode("utf-8")
    parser = Parser(JAVA_LANGUAGE)
    syntax_tree = parser.parse(source_bytes)

    if syntax_tree.root_node.has_error:
        raise ValueError(f"Java 文件存在语法错误：{source_file.relative_path}")

    return syntax_tree
