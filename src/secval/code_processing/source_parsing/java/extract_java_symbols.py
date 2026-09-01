"""从 Java 语法树中提取类和方法符号。"""

from tree_sitter import Node, Tree

from secval.code_processing.code_models import CodeSymbol, SourceFile
from secval.shared_types import SymbolId, create_symbol_id


def extract_java_symbols(
    source_file: SourceFile,
    syntax_tree: Tree,
) -> list[CodeSymbol]:
    """返回 Java 文件中的类和方法符号。"""

    if source_file.language.lower() != "java":
        raise ValueError(
            f"Java 符号提取器不能处理此编程语言：{source_file.language}"
        )


    if syntax_tree.root_node.has_error:
        raise ValueError(f"Java 文件存在语法错误：{source_file.relative_path}")

    source_bytes = source_file.content.encode("utf-8")
    package_name = _find_package_name(syntax_tree.root_node, source_bytes)
    symbols: list[CodeSymbol] = []

    _visit_node(
        node=syntax_tree.root_node,
        source_file=source_file,
        source_bytes=source_bytes,
        package_name=package_name,
        current_class_name=None,
        current_class_id=None,
        symbols=symbols,
    )

    return symbols


def _visit_node(
    node: Node,
    source_file: SourceFile,
    source_bytes: bytes,
    package_name: str,
    current_class_name: str | None,
    current_class_id: SymbolId | None,
    symbols: list[CodeSymbol],
) -> None:
    """访问当前节点，并继续访问它的子节点。"""

    # 子节点默认继续使用当前所属类。
    child_class_name = current_class_name
    child_class_id = current_class_id

    if node.type == "class_declaration":
        class_name_node = node.child_by_field_name("name")

        if class_name_node is None:
            return

        class_name = _node_text(class_name_node, source_bytes)
        class_full_name = _create_class_full_name(
            package_name,
            current_class_name,
            class_name,
        )
        class_id = create_symbol_id(
            repository_id=source_file.repository_id,
            snapshot_id=source_file.snapshot_id,
            relative_path=source_file.relative_path,
            symbol_type="class",
            full_name=class_full_name,
            start_line=node.start_point.row + 1,
        )
        symbols.append(
            CodeSymbol(
                symbol_id=class_id,
                file_id=source_file.file_id,
                repository_id=source_file.repository_id,
                snapshot_id=source_file.snapshot_id,
                symbol_type="class",
                name=class_name,
                full_name=class_full_name,
                start_line=node.start_point.row + 1,
                end_line=node.end_point.row + 1,
                parent_symbol_id=current_class_id,
            )
        )

        # 当前节点是类，所以它的子节点属于这个新发现的类。
        child_class_name = class_full_name
        child_class_id = class_id

    elif node.type == "method_declaration" and current_class_name is not None:
        method_symbol = _create_method_symbol(
            node=node,
            source_file=source_file,
            source_bytes=source_bytes,
            class_full_name=current_class_name,
            class_id=current_class_id,
        )

        if method_symbol is not None:
            symbols.append(method_symbol)

    # 所有节点都从同一个位置继续访问子节点。
    for child_node in node.named_children:
        _visit_node(
            node=child_node,
            source_file=source_file,
            source_bytes=source_bytes,
            package_name=package_name,
            current_class_name=child_class_name,
            current_class_id=child_class_id,
            symbols=symbols,
        )


def _create_method_symbol(
    node: Node,
    source_file: SourceFile,
    source_bytes: bytes,
    class_full_name: str,
    class_id: SymbolId | None,
) -> CodeSymbol | None:
    """根据方法节点创建方法符号。"""

    method_name_node = node.child_by_field_name("name")
    parameters_node = node.child_by_field_name("parameters")

    if method_name_node is None or parameters_node is None:
        return None

    method_name = _node_text(method_name_node, source_bytes)
    parameter_types = _read_parameter_types(parameters_node, source_bytes)
    parameter_text = ",".join(parameter_types)
    method_full_name = f"{class_full_name}.{method_name}({parameter_text})"
    start_line = node.start_point.row + 1
    method_id = create_symbol_id(
        repository_id=source_file.repository_id,
        snapshot_id=source_file.snapshot_id,
        relative_path=source_file.relative_path,
        symbol_type="method",
        full_name=method_full_name,
        start_line=start_line,
    )

    return CodeSymbol(
        symbol_id=method_id,
        file_id=source_file.file_id,
        repository_id=source_file.repository_id,
        snapshot_id=source_file.snapshot_id,
        symbol_type="method",
        name=method_name,
        full_name=method_full_name,
        start_line=start_line,
        end_line=node.end_point.row + 1,
        parent_symbol_id=class_id,
    )


def _read_parameter_types(parameters_node: Node, source_bytes: bytes) -> list[str]:
    """读取方法参数类型，不包含参数变量名。"""

    parameter_types: list[str] = []

    for parameter_node in parameters_node.named_children:
        type_node = parameter_node.child_by_field_name("type")

        if type_node is not None:
            parameter_type = _node_text(type_node, source_bytes)
            parameter_types.append(parameter_type)

    return parameter_types


def _find_package_name(root_node: Node, source_bytes: bytes) -> str:
    """读取 Java 文件的包名；没有 package 声明时返回空字符串。"""

    for child_node in root_node.named_children:
        if child_node.type != "package_declaration":
            continue

        if len(child_node.named_children) == 0:
            return ""

        package_node = child_node.named_children[0]
        return _node_text(package_node, source_bytes)

    return ""


def _create_class_full_name(
    package_name: str,
    parent_class_name: str | None,
    class_name: str,
) -> str:
    """组合包名、上级类名和当前类名。"""

    if parent_class_name is not None:
        return f"{parent_class_name}.{class_name}"

    if package_name:
        return f"{package_name}.{class_name}"

    return class_name


def _node_text(node: Node, source_bytes: bytes) -> str:
    """根据语法节点的字节范围读取原始代码文本。"""

    node_bytes = source_bytes[node.start_byte : node.end_byte]
    return node_bytes.decode("utf-8")
