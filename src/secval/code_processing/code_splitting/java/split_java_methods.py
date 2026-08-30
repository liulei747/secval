"""把 Java 文件中的普通方法切分成 CodeChunk。"""

from tree_sitter import Node, Tree

from secval.code_processing.code_models import CodeChunk, CodeSymbol, SourceFile
from secval.code_processing.source_parsing.java import extract_java_symbols
from secval.shared_types import create_chunk_id


def split_java_methods(
    source_file: SourceFile,
    syntax_tree: Tree,
) -> list[CodeChunk]:
    """提取 Java 普通方法，并为每个方法创建一个代码块。"""

    if source_file.language.lower() != "java":
        raise ValueError(
            f"Java 方法切分器不能处理此编程语言：{source_file.language}"
        )

    symbols = extract_java_symbols(source_file, syntax_tree)
    method_symbols = _find_method_symbols(symbols)
    method_nodes: list[Node] = []

    _find_method_nodes(
        node=syntax_tree.root_node,
        inside_class=False,
        method_nodes=method_nodes,
    )

    if len(method_symbols) != len(method_nodes):
        raise ValueError(
            f"Java 方法符号和语法节点数量不一致：{source_file.relative_path}"
        )

    source_bytes = source_file.content.encode("utf-8")
    chunks: list[CodeChunk] = []

    for index in range(len(method_symbols)):
        method_symbol = method_symbols[index]
        method_node = method_nodes[index]
        method_content = _node_text(method_node, source_bytes)

        if method_symbol.start_line != method_node.start_point.row + 1:
            raise ValueError(
                f"Java 方法符号和语法节点位置不一致：{method_symbol.full_name}"
            )

        chunk_id = create_chunk_id(
            file_id=source_file.file_id,
            chunk_type="method",
            start_line=method_symbol.start_line,
            end_line=method_symbol.end_line,
            content=method_content,
        )
        chunks.append(
            CodeChunk(
                chunk_id=chunk_id,
                file_id=source_file.file_id,
                repository_id=source_file.repository_id,
                snapshot_id=source_file.snapshot_id,
                relative_path=source_file.relative_path,
                language=source_file.language,
                chunk_type="method",
                content=method_content,
                start_line=method_symbol.start_line,
                end_line=method_symbol.end_line,
                symbol_id=method_symbol.symbol_id,
                symbol_name=method_symbol.full_name,
            )
        )

    return chunks


def _find_method_symbols(symbols: list[CodeSymbol]) -> list[CodeSymbol]:
    """从全部符号中选出普通方法符号。"""

    method_symbols: list[CodeSymbol] = []

    for symbol in symbols:
        if symbol.symbol_type == "method":
            method_symbols.append(symbol)

    return method_symbols


def _find_method_nodes(
    node: Node,
    inside_class: bool,
    method_nodes: list[Node],
) -> None:
    """按照语法树顺序找到普通类中的方法节点。"""

    children_are_inside_class = inside_class

    if node.type == "class_declaration":
        children_are_inside_class = True

    elif node.type == "method_declaration" and inside_class:
        method_nodes.append(node)

    for child_node in node.named_children:
        _find_method_nodes(
            node=child_node,
            inside_class=children_are_inside_class,
            method_nodes=method_nodes,
        )


def _node_text(node: Node, source_bytes: bytes) -> str:
    """根据语法节点的字节范围读取方法原文。"""

    node_bytes = source_bytes[node.start_byte : node.end_byte]
    return node_bytes.decode("utf-8")

