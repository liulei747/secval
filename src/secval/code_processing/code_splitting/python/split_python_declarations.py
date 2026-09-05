"""把 Python 文件切成文件头、类和函数代码块。"""

from tree_sitter import Node, Tree

from secval.models.code import CodeChunk, SourceFile
from secval.models.identifiers import create_chunk_id, create_symbol_id


def split_python_declarations(source_file: SourceFile, syntax_tree: Tree) -> list[CodeChunk]:
    if source_file.language.lower() != "python":
        raise ValueError(f"Python代码切块器不能处理此编程语言：{source_file.language}")

    chunks: list[CodeChunk] = []
    declarations = _top_level_declarations(syntax_tree.root_node)
    header_end = declarations[0].start_byte if declarations else len(source_file.content.encode("utf-8"))
    _append_chunk(chunks, source_file, "file", 0, header_end, None)
    for node in syntax_tree.root_node.named_children:
        _visit_node(node, source_file, chunks, [])
    return chunks


def _visit_node(node: Node, source_file: SourceFile, chunks: list[CodeChunk], parents: list[str]):
    if node.type == "decorated_definition":
        declaration = next((child for child in node.named_children
                            if child.type in {"class_definition", "function_definition"}), None)
        if declaration is not None:
            _append_declaration(declaration, source_file, chunks, parents, node.start_byte)
        return
    if node.type in {"class_definition", "function_definition"}:
        _append_declaration(node, source_file, chunks, parents, node.start_byte)
        return
    for child in node.named_children:
        _visit_node(child, source_file, chunks, parents)


def _append_declaration(node, source_file, chunks, parents, content_start):
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    name = source_file.content.encode("utf-8")[name_node.start_byte:name_node.end_byte].decode("utf-8")
    full_name = ".".join([*parents, name])
    chunk_type = "class" if node.type == "class_definition" else "function"
    content_end = node.end_byte
    if chunk_type == "class":
        body = node.child_by_field_name("body")
        if body is not None:
            content_end = body.start_byte
    _append_chunk(chunks, source_file, chunk_type, content_start, content_end, full_name)

    body = node.child_by_field_name("body")
    if body is not None:
        for child in body.named_children:
            _visit_node(child, source_file, chunks, [*parents, name])


def _append_chunk(chunks, source_file, chunk_type, start_byte, end_byte, symbol_name):
    source_bytes = source_file.content.encode("utf-8")
    raw = source_bytes[start_byte:end_byte]
    left_trimmed = raw.lstrip()
    if not left_trimmed:
        return
    start_byte += len(raw) - len(left_trimmed)
    content = left_trimmed.rstrip().decode("utf-8")
    end_byte = start_byte + len(content.encode("utf-8"))
    start_line = source_bytes[:start_byte].count(b"\n") + 1
    end_line = start_line + content.encode("utf-8").count(b"\n")
    line_start = source_bytes.rfind(b"\n", 0, start_byte) + 1
    start_column = start_byte - line_start + 1
    symbol_id = None
    if symbol_name is not None:
        symbol_id = create_symbol_id(source_file.repository_id, source_file.snapshot_id,
                                     source_file.relative_path, chunk_type, symbol_name,
                                     start_line, start_column)
    chunks.append(CodeChunk(
        chunk_id=create_chunk_id(source_file.file_id, chunk_type, start_line, end_line,
                                 content, start_column),
        file_id=source_file.file_id, repository_id=source_file.repository_id,
        snapshot_id=source_file.snapshot_id, relative_path=source_file.relative_path,
        language=source_file.language, chunk_type=chunk_type, content=content,
        start_line=start_line, end_line=end_line, symbol_id=symbol_id,
        symbol_name=symbol_name,
    ))


def _top_level_declarations(root: Node) -> list[Node]:
    declarations = []
    for node in root.named_children:
        if node.type in {"class_definition", "function_definition", "decorated_definition"}:
            declarations.append(node)
    return declarations
