"""把 JavaScript/TypeScript 文件切成文件头、类型、函数和方法代码块。"""

from pathlib import PurePosixPath

from tree_sitter import Node, Tree

from secval.models.code import CodeCall, CodeChunk, SourceFile
from secval.models.identifiers import create_chunk_id, create_symbol_id


def split_javascript_declarations(
    source_file: SourceFile, syntax_tree: Tree
) -> list[CodeChunk]:
    """提取常见 JavaScript 声明，并保留每个函数内的调用线索。"""

    if source_file.language.lower() not in {"javascript", "typescript"}:
        raise ValueError(
            f"JavaScript/TypeScript代码切分器不能处理此编程语言：{source_file.language}"
        )
    source_bytes = source_file.content.encode("utf-8")
    chunks: list[CodeChunk] = []
    declarations = _top_level_declarations(syntax_tree.root_node)
    header_end = declarations[0].start_byte if declarations else len(source_bytes)
    _append_chunk(chunks, source_file, "file", 0, header_end, None, [])

    module_name = _module_name(source_file.relative_path)
    parents = [module_name] if module_name else []
    for node in syntax_tree.root_node.named_children:
        _visit_declaration(node, source_file, chunks, parents)
    return chunks


def _top_level_declarations(root: Node) -> list[Node]:
    declarations = []
    for node in root.named_children:
        if node.type in {
            "abstract_class_declaration", "class_declaration", "enum_declaration",
            "function_declaration", "interface_declaration", "type_alias_declaration"
        }:
            declarations.append(node)
        elif node.type == "export_statement":
            nested = _top_level_declarations(node)
            declarations.extend(nested)
        elif _variable_function(node) is not None:
            declarations.append(node)
    return declarations


def _visit_declaration(node, source_file, chunks, parents):
    if node.type == "export_statement":
        for child in node.named_children:
            _visit_declaration(child, source_file, chunks, parents)
        return
    if node.type in {"abstract_class_declaration", "class_declaration"}:
        _append_class(node, source_file, chunks, parents)
        return
    if node.type in {"enum_declaration", "interface_declaration", "type_alias_declaration"}:
        _append_typescript_type(node, source_file, chunks, parents)
        return
    if node.type == "function_declaration":
        _append_function(node, source_file, chunks, parents)
        return
    variable_function = _variable_function(node)
    if variable_function is not None:
        name_node, function_node = variable_function
        _append_function(
            function_node, source_file, chunks, parents,
            name_node=name_node, content_node=node
        )


def _append_class(node, source_file, chunks, parents):
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    source_bytes = source_file.content.encode("utf-8")
    name = _text(name_node, source_bytes)
    full_name = ".".join([*parents, name])
    body = node.child_by_field_name("body")
    class_end = body.start_byte if body is not None else node.end_byte
    extends_types, implements_types = _typescript_class_relations(
        node, source_bytes
    )
    _append_chunk(
        chunks, source_file, "class", node.start_byte, class_end,
        full_name, [], extends_types=extends_types,
        implements_types=implements_types,
    )
    if body is None:
        return
    for child in body.named_children:
        if child.type == "method_definition":
            _append_method(
                child, source_file, chunks, [*parents, name], owner_node=node
            )


def _append_typescript_type(node, source_file, chunks, parents):
    """保存接口、枚举和类型别名；它们没有可执行函数体。"""

    name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    source_bytes = source_file.content.encode("utf-8")
    name = _text(name_node, source_bytes)
    full_name = ".".join([*parents, name])
    chunk_type = {
        "enum_declaration": "enum",
        "interface_declaration": "interface",
        "type_alias_declaration": "type_alias",
    }[node.type]
    extends_types = []
    if node.type == "interface_declaration":
        extends_types = _typescript_interface_parents(node, source_bytes)
    _append_chunk(
        chunks, source_file, chunk_type, node.start_byte, node.end_byte,
        full_name, [], extends_types=extends_types
    )
    if node.type != "interface_declaration":
        return
    body = node.child_by_field_name("body")
    if body is None:
        return
    for child in body.named_children:
        if child.type == "method_signature":
            _append_method(
                child, source_file, chunks, [*parents, name], owner_node=node
            )


def _typescript_class_relations(node, source_bytes):
    """分别读取类的 extends 和 implements，避免混淆关系方向。"""

    extends_types = []
    implements_types = []
    heritage = next(
        (child for child in node.named_children if child.type == "class_heritage"),
        None,
    )
    if heritage is None:
        return extends_types, implements_types
    for clause in heritage.named_children:
        names = _heritage_type_names(clause, source_bytes)
        if clause.type == "extends_clause":
            extends_types.extend(names)
        elif clause.type == "implements_clause":
            implements_types.extend(names)
    return extends_types, implements_types


def _typescript_interface_parents(node, source_bytes):
    """读取接口 extends 的全部直接父接口。"""

    for child in node.named_children:
        if child.type == "extends_type_clause":
            return _heritage_type_names(child, source_bytes)
    return []


def _heritage_type_names(clause, source_bytes):
    """只接受继承语法节点中的简单类型名；复杂运行时表达式保持未知。"""

    names = []
    for child in clause.named_children:
        if child.type in {"identifier", "nested_type_identifier", "type_identifier"}:
            names.append(_text(child, source_bytes))
    return names


def _append_method(node, source_file, chunks, parents, owner_node):
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    source_bytes = source_file.content.encode("utf-8")
    name = _text(name_node, source_bytes)
    full_name = ".".join([*parents, name])
    calls = _calls(
        node, parents[-1] if parents else None, source_bytes,
        owner_node=owner_node
    )
    parameter_count, required_count, accepts_extra = _parameter_counts(node)
    _append_chunk(
        chunks, source_file, "method", node.start_byte, node.end_byte,
        full_name, calls, parameter_count, accepts_extra,
        required_parameter_count=required_count,
    )


def _append_function(node, source_file, chunks, parents,
                     name_node=None, content_node=None):
    if name_node is None:
        name_node = node.child_by_field_name("name")
    if name_node is None:
        return
    source_bytes = source_file.content.encode("utf-8")
    name = _text(name_node, source_bytes)
    full_name = ".".join([*parents, name])
    calls = _calls(node, None, source_bytes)
    parameter_count, required_count, accepts_extra = _parameter_counts(node)
    selected_node = content_node or node
    _append_chunk(
        chunks, source_file, "function", selected_node.start_byte,
        selected_node.end_byte, full_name, calls, parameter_count,
        accepts_extra, required_parameter_count=required_count,
    )


def _variable_function(node):
    if node.type not in {"lexical_declaration", "variable_declaration"}:
        return None
    declarators = [child for child in node.named_children
                   if child.type == "variable_declarator"]
    if len(declarators) != 1:
        return None
    declarator = declarators[0]
    name_node = declarator.child_by_field_name("name")
    value_node = declarator.child_by_field_name("value")
    if (
        name_node is None
        or name_node.type != "identifier"
        or value_node is None
        or value_node.type not in {"arrow_function", "function_expression"}
    ):
        return None
    return name_node, value_node


def _calls(root: Node, owner_type: str | None, source_bytes: bytes,
           owner_node: Node | None = None) -> list[CodeCall]:
    calls = []
    body = root.child_by_field_name("body")
    if body is None:
        pending = []
    elif body.type == "statement_block":
        pending = list(body.named_children)
    else:
        # 箭头函数可以直接返回表达式，此时函数体本身可能就是调用节点。
        pending = [body]
    while pending:
        current = pending.pop()
        if current.type in {
            "class_declaration", "function_declaration", "function_expression",
            "arrow_function", "method_definition"
        }:
            # 嵌套闭包没有单独切块（仅命名函数声明会切），
            # 其调用应归属外层函数；this 语义在 _receiver_type 中
    # 已按隐式调用保守处理。类声明仍跳过（由类自身的块收集）。
            if current.type not in {"arrow_function", "function_expression"}:
                continue
        if current.type == "call_expression":
            function_node = current.child_by_field_name("function")
            name = _called_name(function_node, source_bytes)
            if name is not None:
                arguments = current.child_by_field_name("arguments")
                argument_count = len(arguments.named_children) if arguments else 0
                calls.append(CodeCall(
                    name=name,
                    line=current.start_point.row + 1,
                    receiver_type=_receiver_type(
                        function_node, root, owner_type, owner_node, source_bytes
                    ),
                    argument_count=argument_count,
                ))
        pending.extend(current.named_children)
    calls.sort(key=lambda call: (call.line, call.name))
    return calls


def _called_name(function_node, source_bytes):
    if function_node is None:
        return None
    if function_node.type == "identifier":
        return _text(function_node, source_bytes)
    if function_node.type not in {"member_expression", "subscript_expression"}:
        return None
    property_node = function_node.child_by_field_name("property")
    if property_node is None:
        return None
    if property_node.type not in {"identifier", "property_identifier"}:
        return None
    return _text(property_node, source_bytes)


def _receiver_type(function_node, root, owner_type, owner_node, source_bytes):
    if function_node is None or function_node.type not in {"member_expression", "identifier"}:
        return None
    object_node = function_node.child_by_field_name("object")
    if object_node is None:
        # JS/TS 的 helper() 查找词法作用域中的变量，不等于 this.helper()。
        # 没有显式接收者时保持未知，避免误连到同名类方法。
        return None
    if object_node.type == "this" and owner_type is not None:
        return owner_type
    if object_node.type == "identifier":
        name = _text(object_node, source_bytes)
        declared_type = _declared_variable_type(
            name, function_node.start_byte, root, source_bytes
        )
        if declared_type is not None:
            return declared_type
        if name and name[0].isupper():
            return name
        return None
    if object_node.type == "member_expression" and owner_node is not None:
        inner_object = object_node.child_by_field_name("object")
        property_node = object_node.child_by_field_name("property")
        if (
            inner_object is not None
            and inner_object.type == "this"
            and property_node is not None
        ):
            return _constructor_property_type(
                _text(property_node, source_bytes), owner_node, source_bytes
            )
    if object_node.type == "new_expression":
        constructor = object_node.child_by_field_name("constructor")
        if constructor is not None and constructor.type == "member_expression":
            # new orders.OrderService() 这类模块成员构造：接收者类型是成员短名，
            # 前缀交给导入别名解析。
            prefix = constructor.child_by_field_name("object")
            property_node = constructor.child_by_field_name("property")
            if (
                prefix is not None
                and prefix.type == "identifier"
                and property_node is not None
            ):
                return _text(property_node, source_bytes)
        if constructor is not None and constructor.type == "identifier":
            return _text(constructor, source_bytes)
    return None


def _declared_variable_type(variable_name, before_byte, root, source_bytes):
    """读取函数参数类型，或调用之前唯一的局部变量明确类型。"""

    parameters = root.child_by_field_name("parameters")
    if parameters is not None:
        for parameter in parameters.named_children:
            if _parameter_name(parameter, source_bytes) == variable_name:
                declared_type = _parameter_type(parameter, source_bytes)
                if declared_type is not None:
                    return declared_type

    candidates = []
    pending = list(root.named_children)
    while pending:
        current = pending.pop()
        if current.start_byte >= before_byte:
            continue
        if current != root and current.type in {
            "arrow_function", "class_declaration", "function_declaration",
            "function_expression", "method_definition"
        }:
            # 闭包按词法作用域可见外层变量；类声明由类块自行收集。
            if current.type not in {"arrow_function", "function_expression"}:
                continue
        if current.type == "variable_declarator":
            name_node = current.child_by_field_name("name")
            if name_node is not None and _text(name_node, source_bytes) == variable_name:
                declared_type = _annotation_type(
                    current.child_by_field_name("type"), source_bytes
                )
                if declared_type is None:
                    value_node = current.child_by_field_name("value")
                    declared_type = _new_expression_type(value_node, source_bytes)
                if declared_type is None and value_node is not None \
                        and value_node.type == "call_expression":
                    declared_type = _call_return_type(value_node, root, source_bytes)
                if declared_type is None and value_node is not None \
                        and value_node.type == "subscript_expression":
                    # 不递归：下标内的数组声明查找不进入另一层下标推断。
                    object_node = value_node.child_by_field_name("object")
                    if object_node is not None and object_node.type == "identifier":
                        array_name = _text(object_node, source_bytes)
                        array_type = _declared_variable_type(
                            array_name, current.start_byte, root, source_bytes,
                        )
                        if (array_type is not None and array_type.endswith("[]")
                                and not array_type[:-2].strip().endswith("[]")):
                            declared_type = array_type[:-2].strip()
                candidates.append(declared_type)
        pending.extend(current.named_children)
    known = {value for value in candidates if value is not None}
    if len(candidates) == 1 and len(known) == 1:
        return next(iter(known))
    return None


def _constructor_property_type(property_name, owner_node, source_bytes):
    """从构造函数参数属性读取 this.xxx 的类型。"""

    body = owner_node.child_by_field_name("body")
    if body is None:
        return None
    for member in body.named_children:
        if member.type != "method_definition":
            continue
        name_node = member.child_by_field_name("name")
        if name_node is None or _text(name_node, source_bytes) != "constructor":
            continue
        parameters = member.child_by_field_name("parameters")
        if parameters is None:
            return None
        for parameter in parameters.named_children:
            is_parameter_property = any(
                child.type in {"accessibility_modifier", "readonly_type"}
                for child in parameter.named_children
            )
            if (
                is_parameter_property
                and _parameter_name(parameter, source_bytes) == property_name
            ):
                return _parameter_type(parameter, source_bytes)
    return None


def _parameter_name(parameter, source_bytes):
    pattern = parameter.child_by_field_name("pattern")
    if pattern is None and parameter.type == "identifier":
        pattern = parameter
    if pattern is None or pattern.type != "identifier":
        return None
    return _text(pattern, source_bytes)


def _parameter_type(parameter, source_bytes):
    return _annotation_type(parameter.child_by_field_name("type"), source_bytes)


def _annotation_type(annotation, source_bytes):
    if annotation is None:
        return None
    named_children = annotation.named_children
    type_node = named_children[0] if named_children else annotation
    # 数组类型保留[]标记：数组对象自身的调用不能记到元素类型上。
    if type_node is not None and type_node.type == 'array_type':
        return _text(type_node, source_bytes)
    if type_node.type not in {'identifier', 'nested_type_identifier', 'type_identifier'}:
        return None
    return _text(type_node, source_bytes)


def _call_return_type(call_node, root, source_bytes):
    """const x = this.method()：从同类方法的返回类型注解读出元素类型。

    只处理 this.method() 形式且方法带返回类型注解；
    泛型实参替换和外部导入方法不做猜测。
    """
    function_node = call_node.child_by_field_name("function")
    if function_node is None or function_node.type != "member_expression":
        return None
    object_node = function_node.child_by_field_name("object")
    property_node = function_node.child_by_field_name("property")
    if object_node is None or object_node.type != "this":
        return None
    if property_node is None:
        return None
    method_name = _text(property_node, source_bytes)
    arguments_node = call_node.child_by_field_name("arguments")
    argument_count = len(arguments_node.named_children) if arguments_node is not None else 0
    owner_node = root
    while owner_node is not None and owner_node.type != "class_declaration":
        owner_node = owner_node.parent
    if owner_node is None:
        return None
    body = owner_node.child_by_field_name("body")
    if body is None:
        return None
    return_types = set()
    for member in body.named_children:
        if member.type != "method_definition":
            continue
        name_node = member.child_by_field_name("name")
        if name_node is None or _text(name_node, source_bytes) != method_name:
            continue
        # 同名重载按参数个数过滤；个数不同不能确定具体重载。
        parameters = member.child_by_field_name("parameters")
        if parameters is not None and len(parameters.named_children) != argument_count:
            continue
        return_type = _annotation_type(
            member.child_by_field_name("return_type"), source_bytes,
        )
        if return_type is not None:
            return_types.add(return_type)
    if len(return_types) == 1:
        return next(iter(return_types))
    return None


def _new_expression_type(value_node, source_bytes):
    if value_node is None or value_node.type != "new_expression":
        return None
    constructor = value_node.child_by_field_name("constructor")
    if constructor is None or constructor.type not in {"identifier", "type_identifier"}:
        return None
    return _text(constructor, source_bytes)


def _parameter_counts(node):
    """返回固定参数总数、必填数，以及是否存在展开参数。"""

    parameters = node.child_by_field_name("parameters")
    if parameters is None:
        return 0, 0, False
    count = 0
    required_count = 0
    accepts_extra = False
    for parameter in parameters.named_children:
        pattern = parameter.child_by_field_name("pattern")
        is_rest = parameter.type == "rest_pattern" or (
            pattern is not None and pattern.type == "rest_pattern"
        )
        if is_rest:
            accepts_extra = True
            continue
        count += 1
        has_default = parameter.type == "assignment_pattern" or (
            parameter.child_by_field_name("value") is not None
        )
        if parameter.type != "optional_parameter" and not has_default:
            required_count += 1
    return count, required_count, accepts_extra


def _module_name(relative_path):
    path = PurePosixPath(relative_path.replace("\\", "/"))
    parts = list(path.parts)
    if not parts:
        return ""
    parts[-1] = parts[-1].rsplit(".", 1)[0]
    return ".".join(parts)


def _append_chunk(chunks, source_file, chunk_type, start_byte, end_byte,
                  symbol_name, code_calls, parameter_count=None,
                  accepts_extra_arguments=False, extends_types=None,
                  implements_types=None, required_parameter_count=None):
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
        symbol_id = create_symbol_id(
            source_file.repository_id, source_file.snapshot_id,
            source_file.relative_path, chunk_type, symbol_name,
            start_line, start_column
        )
    chunks.append(CodeChunk(
        chunk_id=create_chunk_id(
            source_file.file_id, chunk_type, start_line, end_line,
            content, start_column
        ),
        file_id=source_file.file_id,
        repository_id=source_file.repository_id,
        snapshot_id=source_file.snapshot_id,
        relative_path=source_file.relative_path,
        language=source_file.language,
        chunk_type=chunk_type,
        content=content,
        start_line=start_line,
        end_line=end_line,
        symbol_id=symbol_id,
        symbol_name=symbol_name,
        code_calls=code_calls,
        parameter_count=parameter_count,
        required_parameter_count=required_parameter_count,
        accepts_extra_arguments=accepts_extra_arguments,
        extends_types=list(extends_types or []),
        implements_types=list(implements_types or []),
    ))


def _text(node, source_bytes):
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8")
