"""把 Java 文件中的可搜索声明切分成 CodeChunk。"""

from collections import OrderedDict

from tree_sitter import Tree

from secval.code_processing.source_parsing.java.extract_java_symbols import (
    JavaSymbolNode,
    extract_java_symbol_nodes,
)
from secval.models.code import CodeChunk, SourceFile
from secval.shared_types import create_chunk_id


def split_java_declarations(
    source_file: SourceFile,
    syntax_tree: Tree,
) -> list[CodeChunk]:
    """按声明范围生成去重代码块，同时保留块关联的全部符号。"""

    if source_file.language.lower() != "java":
        raise ValueError(
            f"Java 代码切分器不能处理此编程语言：{source_file.language}"
        )

    symbol_nodes = extract_java_symbol_nodes(source_file, syntax_tree)
    grouped_nodes = _group_shared_declarations(symbol_nodes)
    source_bytes = source_file.content.encode("utf-8")
    chunks: list[CodeChunk] = []

    for declaration_nodes in grouped_nodes.values():
        first_node = declaration_nodes[0]
        content_range = _trim_content_range(
            source_bytes,
            first_node.content_start_byte,
            first_node.content_end_byte,
        )
        if content_range is None:
            continue
        content_start_byte, content_end_byte = content_range
        content_bytes = source_bytes[content_start_byte:content_end_byte]
        content = content_bytes.decode("utf-8")
        start_line = source_bytes[:content_start_byte].count(b"\n") + 1
        end_line = start_line + content_bytes.count(b"\n")
        line_start_byte = source_bytes.rfind(
            b"\n",
            0,
            content_start_byte,
        ) + 1
        start_column = content_start_byte - line_start_byte + 1
        symbols = [item.symbol for item in declaration_nodes]
        symbol_ids = [symbol.symbol_id for symbol in symbols]
        symbol_names = [symbol.full_name for symbol in symbols]
        symbol_id = symbol_ids[0] if len(symbol_ids) == 1 else None
        symbol_name = (
            symbol_names[0]
            if len(symbol_names) == 1
            else ", ".join(symbol_names)
        )
        chunk_id = create_chunk_id(
            file_id=source_file.file_id,
            chunk_type=first_node.chunk_type,
            start_line=start_line,
            end_line=end_line,
            content=content,
            start_column=start_column,
        )
        chunks.append(
            CodeChunk(
                chunk_id=chunk_id,
                file_id=source_file.file_id,
                repository_id=source_file.repository_id,
                snapshot_id=source_file.snapshot_id,
                relative_path=source_file.relative_path,
                language=source_file.language,
                chunk_type=first_node.chunk_type,
                content=content,
                start_line=start_line,
                end_line=end_line,
                symbol_id=symbol_id,
                symbol_name=symbol_name,
                symbol_ids=symbol_ids,
                symbol_names=symbol_names,
            )
        )

    return chunks


def _group_shared_declarations(
    symbol_nodes: list[JavaSymbolNode],
) -> OrderedDict[tuple[str, int, int], list[JavaSymbolNode]]:
    """合并同一条多字段声明，其他代码单元仍保持独立。"""

    grouped: OrderedDict[tuple[str, int, int], list[JavaSymbolNode]] = (
        OrderedDict()
    )
    for item in symbol_nodes:
        key = (
            item.chunk_type,
            item.content_start_byte,
            item.content_end_byte,
        )
        grouped.setdefault(key, []).append(item)
    return grouped


def _trim_content_range(
    source_bytes: bytes,
    start_byte: int,
    end_byte: int,
) -> tuple[int, int] | None:
    """去掉范围两侧空白，并保留修正后的原始字节位置。"""

    raw_content = source_bytes[start_byte:end_byte]
    stripped_left = raw_content.lstrip()
    if not stripped_left:
        return None
    left_offset = len(raw_content) - len(stripped_left)
    stripped_content = stripped_left.rstrip()
    right_offset = len(stripped_left) - len(stripped_content)
    return start_byte + left_offset, end_byte - right_offset
