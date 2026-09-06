"""TypeScript 与 JavaScript 共享声明和调用切块规则。"""

from tree_sitter import Tree

from secval.code_processing.code_splitting.javascript import (
    split_javascript_declarations,
)
from secval.models.code import CodeChunk, SourceFile


def split_typescript_declarations(
    source_file: SourceFile, syntax_tree: Tree
) -> list[CodeChunk]:
    """复用 ECMAScript 主体结构；TypeScript独有声明由共享切块器识别。"""

    if source_file.language.lower() != "typescript":
        raise ValueError(
            f"TypeScript代码切分器不能处理此编程语言：{source_file.language}"
        )
    return split_javascript_declarations(source_file, syntax_tree)
