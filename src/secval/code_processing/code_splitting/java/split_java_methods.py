"""保留旧方法名的 Java 声明切分兼容入口。"""

from tree_sitter import Tree

from secval.code_processing.code_models import CodeChunk, SourceFile
from secval.code_processing.code_splitting.java.split_java_declarations import (
    split_java_declarations,
)


def split_java_methods(
    source_file: SourceFile,
    syntax_tree: Tree,
) -> list[CodeChunk]:
    """兼容旧调用，只返回完整声明切分结果中的普通方法块。"""

    return [
        chunk
        for chunk in split_java_declarations(source_file, syntax_tree)
        if chunk.chunk_type == "method"
    ]

