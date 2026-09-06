"""使用 Tree-sitter 解析 TypeScript 和 TSX 源代码。"""

import tree_sitter_typescript
from tree_sitter import Language, Parser, Tree

from secval.models.code import SourceFile


TYPESCRIPT_LANGUAGE = Language(tree_sitter_typescript.language_typescript())
TSX_LANGUAGE = Language(tree_sitter_typescript.language_tsx())


def parse_typescript(source_file: SourceFile) -> Tree:
    """根据文件扩展名选择 TypeScript 或 TSX 语法。"""

    if source_file.language.lower() != "typescript":
        raise ValueError(
            f"TypeScript解析器不能处理此编程语言：{source_file.language}"
        )
    language = TSX_LANGUAGE if source_file.relative_path.lower().endswith(".tsx") else TYPESCRIPT_LANGUAGE
    syntax_tree = Parser(language).parse(source_file.content.encode("utf-8"))
    if syntax_tree.root_node.has_error:
        raise ValueError(f"TypeScript语法解析失败：{source_file.relative_path}")
    return syntax_tree
