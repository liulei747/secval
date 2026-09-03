"""从 Java 语法树中提取可搜索代码符号及其来源节点。"""

import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import PurePosixPath

from tree_sitter import Node, Tree

from secval.models.code import CodeSymbol, SourceFile
from secval.shared_types import SymbolId, create_symbol_id

TYPE_DECLARATIONS = {
    "class_declaration": "class",
    "interface_declaration": "interface",
    "enum_declaration": "enum",
    "annotation_type_declaration": "annotation",
    "record_declaration": "record",
}


@dataclass(frozen=True)
class JavaSymbolNode:
    """把一个代码符号和生成检索块所需的源码范围绑定在一起。"""

    symbol: CodeSymbol
    node: Node
    chunk_type: str
    content_start_byte: int
    content_end_byte: int


@dataclass(frozen=True)
class _Owner:
    """遍历语法树时记录当前符号所属的直接上级。"""

    symbol_id: SymbolId
    full_name: str
    symbol_type: str
    record_parameter_types: tuple[str, ...] = ()


def extract_java_symbols(
    source_file: SourceFile,
    syntax_tree: Tree,
) -> list[CodeSymbol]:
    """返回文件、类型、成员和初始化块等全部可搜索 Java 符号。"""

    symbols: list[CodeSymbol] = []
    seen_symbol_ids: set[SymbolId] = set()
    for item in extract_java_symbol_nodes(source_file, syntax_tree):
        if item.symbol.symbol_id in seen_symbol_ids:
            continue
        seen_symbol_ids.add(item.symbol.symbol_id)
        symbols.append(item.symbol)
    return symbols


def extract_java_symbol_nodes(
    source_file: SourceFile,
    syntax_tree: Tree,
) -> list[JavaSymbolNode]:
    """提取 Java 符号，并保留每个符号对应的 Tree-sitter 节点。"""

    _validate_java_input(source_file, syntax_tree)
    source_bytes = source_file.content.encode("utf-8")
    root_node = syntax_tree.root_node
    package_name = _find_package_name(root_node, source_bytes)
    file_symbol = _create_symbol(
        source_file=source_file,
        symbol_type="file",
        name=PurePosixPath(source_file.relative_path).name,
        full_name=source_file.relative_path,
        node=root_node,
        parent_symbol_id=None,
    )
    file_owner = _Owner(
        symbol_id=file_symbol.symbol_id,
        full_name=file_symbol.full_name,
        symbol_type="file",
    )
    symbol_nodes: list[JavaSymbolNode] = []

    for child_node in root_node.named_children:
        _visit_node(
            node=child_node,
            parent_type=root_node.type,
            source_file=source_file,
            source_bytes=source_bytes,
            package_name=package_name,
            owner=file_owner,
            symbol_nodes=symbol_nodes,
        )

    header_end_byte = _find_file_header_end(
        root_node,
        symbol_nodes,
        source_bytes,
    )
    symbol_nodes.insert(
        0,
        JavaSymbolNode(
            symbol=file_symbol,
            node=root_node,
            chunk_type="file",
            content_start_byte=root_node.start_byte,
            content_end_byte=header_end_byte,
        ),
    )
    _add_uncovered_file_comments(
        root_node,
        source_bytes,
        file_symbol,
        symbol_nodes,
    )
    return symbol_nodes


def _visit_node(
    node: Node,
    parent_type: str,
    source_file: SourceFile,
    source_bytes: bytes,
    package_name: str,
    owner: _Owner,
    symbol_nodes: list[JavaSymbolNode],
) -> None:
    """用显式栈深度优先遍历，避免深表达式触发 Python 递归上限。"""

    pending_nodes: list[tuple[Node, str, _Owner]] = [
        (node, parent_type, owner)
    ]

    while pending_nodes:
        current_node, current_parent_type, current_owner = pending_nodes.pop()
        child_owner = current_owner
        anonymous_body_node: Node | None = None

        if current_node.type in TYPE_DECLARATIONS:
            child_owner = _add_type_declaration(
                current_node,
                source_file,
                source_bytes,
                package_name,
                current_owner,
                symbol_nodes,
            )
        elif current_node.type == "module_declaration":
            child_owner = _add_module_declaration(
                current_node,
                source_file,
                source_bytes,
                current_owner,
                symbol_nodes,
            )
        elif current_node.type == "method_declaration":
            child_owner = _add_callable_declaration(
                current_node,
                "method",
                source_file,
                source_bytes,
                current_owner,
                symbol_nodes,
            )
        elif current_node.type in {
            "constructor_declaration",
            "compact_constructor_declaration",
        }:
            child_owner = _add_callable_declaration(
                current_node,
                "constructor",
                source_file,
                source_bytes,
                current_owner,
                symbol_nodes,
            )
        elif current_node.type == "annotation_type_element_declaration":
            child_owner = _add_annotation_element(
                current_node,
                source_file,
                source_bytes,
                current_owner,
                symbol_nodes,
            )
        elif current_node.type in {
            "field_declaration",
            "constant_declaration",
        }:
            field_children = _add_field_declaration(
                current_node,
                source_file,
                source_bytes,
                current_owner,
                symbol_nodes,
            )
            pending_nodes.extend(reversed(field_children))
            continue
        elif current_node.type == "enum_constant":
            child_owner = _add_named_declaration(
                current_node,
                "enum_constant",
                source_file,
                source_bytes,
                current_owner,
                symbol_nodes,
            )
        elif current_node.type == "static_initializer":
            child_owner = _add_initializer(
                current_node,
                "static_initializer",
                "<clinit>",
                source_file,
                source_bytes,
                current_owner,
                symbol_nodes,
            )
        elif current_node.type == "block" and current_parent_type in {
            "class_body",
            "enum_body_declarations",
        }:
            child_owner = _add_initializer(
                current_node,
                "initializer",
                "<init-block>",
                source_file,
                source_bytes,
                current_owner,
                symbol_nodes,
            )
        elif current_node.type == "object_creation_expression":
            anonymous_body_node = _find_named_child(
                current_node,
                "class_body",
            )
            if anonymous_body_node is not None:
                child_owner = _add_anonymous_class(
                    current_node,
                    anonymous_body_node,
                    source_file,
                    source_bytes,
                    current_owner,
                    symbol_nodes,
                )

        child_entries: list[tuple[Node, str, _Owner]] = []
        for child_node in current_node.named_children:
            owner_for_child = child_owner
            if (
                anonymous_body_node is not None
                and child_node.id != anonymous_body_node.id
            ):
                owner_for_child = current_owner
            child_entries.append(
                (child_node, current_node.type, owner_for_child)
            )
        pending_nodes.extend(reversed(child_entries))


def _add_type_declaration(
    node: Node,
    source_file: SourceFile,
    source_bytes: bytes,
    package_name: str,
    owner: _Owner,
    symbol_nodes: list[JavaSymbolNode],
) -> _Owner:
    """加入类、接口、枚举、注解类型或记录类型。"""

    name_node = node.child_by_field_name("name")
    if name_node is None:
        return owner

    name = _node_text(name_node, source_bytes)
    full_name_part = name
    if _is_local_type_declaration(node):
        full_name_part = (
            f"{name}@{node.start_point.row + 1}:{node.start_point.column + 1}"
        )
    full_name = _create_type_full_name(package_name, owner, full_name_part)
    symbol_type = TYPE_DECLARATIONS[node.type]
    symbol = _create_symbol(
        source_file,
        symbol_type,
        name,
        full_name,
        node,
        owner.symbol_id,
    )
    body_node = node.child_by_field_name("body")
    content_end_byte = body_node.start_byte if body_node is not None else node.end_byte
    symbol_nodes.append(
        _create_symbol_node(
            symbol,
            node,
            symbol_type,
            source_bytes,
            content_end_byte=content_end_byte,
        )
    )

    record_parameter_types: tuple[str, ...] = ()
    if node.type == "record_declaration":
        parameters_node = node.child_by_field_name("parameters")
        if parameters_node is not None:
            record_parameter_types = tuple(
                _read_parameter_types(parameters_node, source_bytes)
            )
            _add_record_components(
                parameters_node,
                source_file,
                source_bytes,
                symbol,
                symbol_nodes,
            )

    return _Owner(
        symbol_id=symbol.symbol_id,
        full_name=symbol.full_name,
        symbol_type=symbol_type,
        record_parameter_types=record_parameter_types,
    )


def _add_module_declaration(
    node: Node,
    source_file: SourceFile,
    source_bytes: bytes,
    owner: _Owner,
    symbol_nodes: list[JavaSymbolNode],
) -> _Owner:
    """加入 module-info.java 中的模块声明。"""

    name_node = node.child_by_field_name("name")
    if name_node is None and node.named_children:
        name_node = node.named_children[0]
    if name_node is None:
        return owner
    name = _node_text(name_node, source_bytes)
    symbol = _create_symbol(
        source_file, "module", name, name, node, owner.symbol_id
    )
    symbol_nodes.append(_create_symbol_node(symbol, node, "module", source_bytes))
    return _Owner(symbol.symbol_id, symbol.full_name, "module")


def _add_callable_declaration(
    node: Node,
    symbol_type: str,
    source_file: SourceFile,
    source_bytes: bytes,
    owner: _Owner,
    symbol_nodes: list[JavaSymbolNode],
) -> _Owner:
    """加入方法、普通构造函数或记录紧凑构造函数。"""

    name_node = node.child_by_field_name("name")
    if name_node is None:
        return owner
    name = _node_text(name_node, source_bytes)
    parameters_node = node.child_by_field_name("parameters")
    if parameters_node is not None:
        parameter_types = _read_parameter_types(parameters_node, source_bytes)
    elif node.type == "compact_constructor_declaration":
        parameter_types = list(owner.record_parameter_types)
    else:
        parameter_types = []
    parameter_text = ",".join(parameter_types)
    full_name = f"{owner.full_name}.{name}({parameter_text})"
    symbol = _create_symbol(
        source_file,
        symbol_type,
        name,
        full_name,
        node,
        owner.symbol_id,
    )
    symbol_nodes.append(
        _create_symbol_node(symbol, node, symbol_type, source_bytes)
    )
    return _Owner(symbol.symbol_id, symbol.full_name, symbol_type)


def _add_annotation_element(
    node: Node,
    source_file: SourceFile,
    source_bytes: bytes,
    owner: _Owner,
    symbol_nodes: list[JavaSymbolNode],
) -> _Owner:
    """加入注解类型中声明的元素。"""

    name_node = node.child_by_field_name("name")
    if name_node is None:
        return owner
    name = _node_text(name_node, source_bytes)
    symbol = _create_symbol(
        source_file,
        "annotation_element",
        name,
        f"{owner.full_name}.{name}()",
        node,
        owner.symbol_id,
    )
    symbol_nodes.append(
        _create_symbol_node(
            symbol, node, "annotation_element", source_bytes
        )
    )
    return _Owner(symbol.symbol_id, symbol.full_name, "annotation_element")


def _add_field_declaration(
    node: Node,
    source_file: SourceFile,
    source_bytes: bytes,
    owner: _Owner,
    symbol_nodes: list[JavaSymbolNode],
) -> list[tuple[Node, str, _Owner]]:
    """创建字段符号，并返回带具体字段 owner 的待遍历子节点。"""

    declarator_nodes = list(node.children_by_field_name("declarator"))
    declarator_owners: dict[int, _Owner] = {}

    for declarator_node in declarator_nodes:
        name_node = _find_declarator_name(declarator_node)
        if name_node is None:
            continue
        name = _node_text(name_node, source_bytes)
        symbol = _create_symbol(
            source_file,
            "field",
            name,
            f"{owner.full_name}.{name}",
            declarator_node,
            owner.symbol_id,
        )
        symbol_nodes.append(
            _create_symbol_node(symbol, node, "field", source_bytes)
        )
        declarator_owners[declarator_node.id] = _Owner(
            symbol.symbol_id,
            symbol.full_name,
            "field",
        )

    child_entries: list[tuple[Node, str, _Owner]] = []
    for child_node in node.named_children:
        child_entries.append(
            (
                child_node,
                node.type,
                declarator_owners.get(child_node.id, owner),
            )
        )
    return child_entries


def _add_named_declaration(
    node: Node,
    symbol_type: str,
    source_file: SourceFile,
    source_bytes: bytes,
    owner: _Owner,
    symbol_nodes: list[JavaSymbolNode],
) -> _Owner:
    """加入具有 name 字段、但没有参数签名的成员声明。"""

    name_node = node.child_by_field_name("name")
    if name_node is None:
        return owner
    name = _node_text(name_node, source_bytes)
    symbol = _create_symbol(
        source_file,
        symbol_type,
        name,
        f"{owner.full_name}.{name}",
        node,
        owner.symbol_id,
    )
    body_node = node.child_by_field_name("body")
    symbol_nodes.append(
        _create_symbol_node(
            symbol,
            node,
            symbol_type,
            source_bytes,
            content_end_byte=(
                body_node.start_byte if body_node is not None else None
            ),
        )
    )
    return _Owner(symbol.symbol_id, symbol.full_name, symbol_type)


def _add_initializer(
    node: Node,
    symbol_type: str,
    display_name: str,
    source_file: SourceFile,
    source_bytes: bytes,
    owner: _Owner,
    symbol_nodes: list[JavaSymbolNode],
) -> _Owner:
    """加入静态初始化块或实例初始化块。"""

    line_number = node.start_point.row + 1
    column_number = node.start_point.column + 1
    name = f"{display_name}@{line_number}:{column_number}"
    symbol = _create_symbol(
        source_file,
        symbol_type,
        name,
        f"{owner.full_name}.{name}",
        node,
        owner.symbol_id,
    )
    symbol_nodes.append(
        _create_symbol_node(symbol, node, symbol_type, source_bytes)
    )
    return _Owner(symbol.symbol_id, symbol.full_name, symbol_type)


def _add_anonymous_class(
    node: Node,
    body_node: Node,
    source_file: SourceFile,
    source_bytes: bytes,
    owner: _Owner,
    symbol_nodes: list[JavaSymbolNode],
) -> _Owner:
    """加入带类体的匿名类，并让其中的方法归属于该匿名类。"""

    line_number = node.start_point.row + 1
    column_number = node.start_point.column + 1
    name = f"<anonymous>@{line_number}:{column_number}"
    symbol = _create_symbol(
        source_file,
        "anonymous_class",
        name,
        f"{owner.full_name}.{name}",
        node,
        owner.symbol_id,
    )
    symbol_nodes.append(
        _create_symbol_node(
            symbol,
            node,
            "anonymous_class",
            source_bytes,
            content_end_byte=body_node.start_byte,
        )
    )
    return _Owner(symbol.symbol_id, symbol.full_name, "anonymous_class")


def _add_record_components(
    parameters_node: Node,
    source_file: SourceFile,
    source_bytes: bytes,
    record_symbol: CodeSymbol,
    symbol_nodes: list[JavaSymbolNode],
) -> None:
    """把记录头部的每个组件作为独立字段式符号。"""

    for parameter_node in parameters_node.named_children:
        name_node = parameter_node.child_by_field_name("name")
        if name_node is None:
            declarator_node = _find_named_child(
                parameter_node, "variable_declarator"
            )
            if declarator_node is not None:
                name_node = _find_declarator_name(declarator_node)
        if name_node is None:
            continue
        name = _node_text(name_node, source_bytes)
        symbol = _create_symbol(
            source_file,
            "record_component",
            name,
            f"{record_symbol.full_name}.{name}",
            parameter_node,
            record_symbol.symbol_id,
        )
        symbol_nodes.append(
            _create_symbol_node(
                symbol,
                parameter_node,
                "record_component",
                source_bytes,
                include_leading_comment=False,
            )
        )


def _create_symbol(
    source_file: SourceFile,
    symbol_type: str,
    name: str,
    full_name: str,
    node: Node,
    parent_symbol_id: SymbolId | None,
) -> CodeSymbol:
    """根据公共来源字段创建一个稳定 CodeSymbol。"""

    symbol_id = create_symbol_id(
        repository_id=source_file.repository_id,
        snapshot_id=source_file.snapshot_id,
        relative_path=source_file.relative_path,
        symbol_type=symbol_type,
        full_name=full_name,
        start_line=node.start_point.row + 1,
        start_column=node.start_point.column + 1,
    )
    return CodeSymbol(
        symbol_id=symbol_id,
        file_id=source_file.file_id,
        repository_id=source_file.repository_id,
        snapshot_id=source_file.snapshot_id,
        symbol_type=symbol_type,
        name=name,
        full_name=full_name,
        start_line=node.start_point.row + 1,
        end_line=node.end_point.row + 1,
        parent_symbol_id=parent_symbol_id,
    )


def _create_symbol_node(
    symbol: CodeSymbol,
    node: Node,
    chunk_type: str,
    source_bytes: bytes,
    content_end_byte: int | None = None,
    include_leading_comment: bool = True,
) -> JavaSymbolNode:
    """创建带源码范围的符号节点，并纳入紧邻的文档注释。"""

    content_start_byte = node.start_byte
    if include_leading_comment:
        content_start_byte = _find_leading_comment_start(node, source_bytes)
    return JavaSymbolNode(
        symbol=symbol,
        node=node,
        chunk_type=chunk_type,
        content_start_byte=content_start_byte,
        content_end_byte=(
            node.end_byte if content_end_byte is None else content_end_byte
        ),
    )


def _read_parameter_types(parameters_node: Node, source_bytes: bytes) -> list[str]:
    """读取方法、构造函数或记录组件的参数类型。"""

    parameter_types: list[str] = []
    for parameter_node in parameters_node.named_children:
        if parameter_node.type == "receiver_parameter":
            continue
        type_node = parameter_node.child_by_field_name("type")
        if type_node is None and parameter_node.type == "spread_parameter":
            type_node = _find_spread_parameter_type(parameter_node)
        if type_node is None:
            continue
        parameter_type = _normalize_java_type(
            _node_text(type_node, source_bytes)
        )
        dimensions_node = parameter_node.child_by_field_name("dimensions")
        if dimensions_node is None:
            declarator_node = _find_named_child(
                parameter_node, "variable_declarator"
            )
            if declarator_node is not None:
                dimensions_node = declarator_node.child_by_field_name(
                    "dimensions"
                )
        if dimensions_node is not None:
            parameter_type += _normalize_java_type(
                _node_text(dimensions_node, source_bytes)
            )
        if parameter_node.type == "spread_parameter":
            parameter_type += "..."
        parameter_types.append(parameter_type)
    return parameter_types


def _find_package_name(root_node: Node, source_bytes: bytes) -> str:
    """读取包名；默认包返回空字符串。"""

    for child_node in root_node.named_children:
        if child_node.type != "package_declaration":
            continue
        for package_child in child_node.named_children:
            if package_child.type in {"identifier", "scoped_identifier"}:
                return _node_text(package_child, source_bytes)
        return ""
    return ""


def _create_type_full_name(package_name: str, owner: _Owner, name: str) -> str:
    """组合包名以及嵌套符号名称。"""

    if owner.symbol_type != "file":
        return f"{owner.full_name}.{name}"
    if package_name:
        return f"{package_name}.{name}"
    return name


def _find_leading_comment_start(node: Node, source_bytes: bytes) -> int:
    """把与声明相邻的行注释或块注释一并纳入代码块。"""

    start_byte = node.start_byte
    sibling = node.prev_named_sibling
    while sibling is not None and sibling.type in {"line_comment", "block_comment"}:
        between = source_bytes[sibling.end_byte:start_byte]
        if between.strip():
            break
        start_byte = sibling.start_byte
        sibling = sibling.prev_named_sibling
    return start_byte


def _find_file_header_end(
    root_node: Node,
    symbol_nodes: list[JavaSymbolNode],
    source_bytes: bytes,
) -> int:
    """文件块只覆盖首个顶层类型或模块之前的 package/import/注释。"""

    top_level_items = [
        item
        for item in symbol_nodes
        if item.symbol.symbol_type in {*TYPE_DECLARATIONS.values(), "module"}
        and item.node.parent == root_node
    ]
    if top_level_items:
        first_item = min(
            top_level_items,
            key=lambda item: item.content_start_byte,
        )
        header_end_byte = first_item.content_start_byte
        header_content = source_bytes[root_node.start_byte:header_end_byte]
        if header_content.strip():
            return header_end_byte
        # 默认包且没有文件头时，复用第一个类型的短声明头，确保每个
        # 非空 Java 文件仍有一个可按路径命中的 file 块。
        body_node = first_item.node.child_by_field_name("body")
        if body_node is not None:
            return body_node.start_byte
        return first_item.content_end_byte
    return root_node.end_byte


def _add_uncovered_file_comments(
    root_node: Node,
    source_bytes: bytes,
    file_symbol: CodeSymbol,
    symbol_nodes: list[JavaSymbolNode],
) -> None:
    """把未落入任何声明块的尾部/间隔注释保留为 file 搜索块。"""

    covered_ranges = _merge_byte_ranges(
        [
            (item.content_start_byte, item.content_end_byte)
            for item in symbol_nodes
        ]
    )
    covered_starts = [start_byte for start_byte, _ in covered_ranges]
    pending_nodes = [root_node]

    while pending_nodes:
        node = pending_nodes.pop()
        if node.type in {"line_comment", "block_comment"}:
            range_index = bisect_right(covered_starts, node.start_byte) - 1
            is_covered = (
                range_index >= 0
                and node.end_byte <= covered_ranges[range_index][1]
            )
            if not is_covered:
                symbol_nodes.append(
                    JavaSymbolNode(
                        symbol=file_symbol,
                        node=node,
                        chunk_type="file",
                        content_start_byte=node.start_byte,
                        content_end_byte=node.end_byte,
                    )
                )
            continue
        pending_nodes.extend(node.named_children)


def _merge_byte_ranges(
    ranges: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    """合并重叠声明范围，供注释覆盖检查进行二分查找。"""

    merged_ranges: list[tuple[int, int]] = []
    for start_byte, end_byte in sorted(ranges):
        if not merged_ranges or start_byte > merged_ranges[-1][1]:
            merged_ranges.append((start_byte, end_byte))
            continue
        previous_start, previous_end = merged_ranges[-1]
        merged_ranges[-1] = (previous_start, max(previous_end, end_byte))
    return merged_ranges


def _is_local_type_declaration(node: Node) -> bool:
    """按实际语法容器区分成员类型与表达式/代码块中的局部类型。"""

    if node.parent is None:
        return False
    member_container_types = {
        "program",
        "class_body",
        "interface_body",
        "enum_body_declarations",
        "annotation_type_body",
    }
    return node.parent.type not in member_container_types


def _validate_java_input(source_file: SourceFile, syntax_tree: Tree) -> None:
    """拒绝错误语言和包含语法错误的树。"""

    if source_file.language.lower() != "java":
        raise ValueError(
            f"Java 符号提取器不能处理此编程语言：{source_file.language}"
        )
    if syntax_tree.root_node.has_error:
        raise ValueError(f"Java 文件存在语法错误：{source_file.relative_path}")


def _node_text(node: Node, source_bytes: bytes) -> str:
    """根据语法节点的 UTF-8 字节范围读取原始文本。"""

    return source_bytes[node.start_byte : node.end_byte].decode("utf-8")


def _find_named_child(node: Node, node_type: str) -> Node | None:
    """按节点类型查找直接命名子节点。"""

    for child_node in node.named_children:
        if child_node.type == node_type:
            return child_node
    return None


def _find_declarator_name(declarator_node: Node) -> Node | None:
    """读取变量声明器名称。"""

    name_node = declarator_node.child_by_field_name("name")
    if name_node is not None:
        return name_node
    return _find_named_child(declarator_node, "identifier")


def _find_spread_parameter_type(parameter_node: Node) -> Node | None:
    """读取 Tree-sitter 未标注 field name 的可变参数类型节点。"""

    ignored_types = {
        "modifiers",
        "annotation",
        "marker_annotation",
        "variable_declarator",
    }
    for child_node in parameter_node.named_children:
        if child_node.type not in ignored_types:
            return child_node
    return None


def _normalize_java_type(type_text: str) -> str:
    """去掉类型中的注释并规范空白，生成稳定的签名文本。"""

    without_comments = _remove_java_comments(type_text)
    normalized = " ".join(without_comments.split())
    return re.sub(r"\s*([<>\[\],.])\s*", r"\1", normalized)


def _remove_java_comments(text: str) -> str:
    """只删除真实 Java 注释，保留字符串和字符字面量中的注释标记。"""

    result: list[str] = []
    index = 0
    quote_delimiter: str | None = None

    while index < len(text):
        if quote_delimiter is not None:
            if text.startswith(quote_delimiter, index):
                result.append(quote_delimiter)
                index += len(quote_delimiter)
                quote_delimiter = None
                continue
            if text[index] == "\\" and index + 1 < len(text):
                result.append(text[index : index + 2])
                index += 2
                continue
            result.append(text[index])
            index += 1
            continue

        if text.startswith("//", index):
            line_end = text.find("\n", index + 2)
            result.append(" ")
            index = len(text) if line_end == -1 else line_end + 1
            continue
        if text.startswith("/*", index):
            comment_end = text.find("*/", index + 2)
            result.append(" ")
            index = len(text) if comment_end == -1 else comment_end + 2
            continue
        if text.startswith('"""', index):
            quote_delimiter = '"""'
            result.append(quote_delimiter)
            index += 3
            continue
        if text[index] in {'"', "'"}:
            quote_delimiter = text[index]
            result.append(text[index])
            index += 1
            continue
        result.append(text[index])
        index += 1

    return "".join(result)
