"""把 Python 文件切成文件头、类和函数代码块。"""

from dataclasses import dataclass, field
from pathlib import PurePosixPath

from tree_sitter import Node, Tree

from secval.models.code import CodeCall, CodeChunk, SourceFile
from secval.models.identifiers import create_chunk_id, create_symbol_id


@dataclass
class PythonParameterInfo:
    """保存调用匹配需要的 Python 参数规则。"""

    total_count: int = 0
    required_count: int = 0
    accepts_extra_arguments: bool = False
    positional_count: int = 0
    keyword_names: list[str] = field(default_factory=list)
    required_keyword_only_names: list[str] = field(default_factory=list)
    accepts_extra_keywords: bool = False
    has_default_parameters: bool = False


def split_python_declarations(source_file: SourceFile, syntax_tree: Tree) -> list[CodeChunk]:
    if source_file.language.lower() != "python":
        raise ValueError(f"Python代码切块器不能处理此编程语言：{source_file.language}")

    chunks: list[CodeChunk] = []
    module_name = _python_module_name(source_file.relative_path)
    declarations = _top_level_declarations(syntax_tree.root_node)
    header_end = declarations[0].start_byte if declarations else len(source_file.content.encode("utf-8"))
    _append_chunk(chunks, source_file, "file", 0, header_end, None)
    for node in syntax_tree.root_node.named_children:
        _visit_node(node, source_file, chunks, [module_name] if module_name else [])
    return chunks


def _python_module_name(relative_path: str) -> str:
    """把 first/service.py 转成 first.service，包入口不保留 __init__。"""

    path = PurePosixPath(relative_path.replace("\\", "/"))
    parts = list(path.parts)
    if not parts:
        return ""
    file_name = parts[-1]
    stem = file_name.rsplit(".", 1)[0]
    if stem == "__init__":
        parts = parts[:-1]
    else:
        parts[-1] = stem
    return ".".join(part for part in parts if part not in {"", "."})


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
    extends_types = []
    if chunk_type == "class":
        extends_types = _superclass_types(node, source_file.content.encode("utf-8"))
    content_end = node.end_byte
    if chunk_type == "class":
        body = node.child_by_field_name("body")
        if body is not None:
            content_end = body.start_byte
    code_calls = []
    parameter_count = None
    required_parameter_count = None
    accepts_extra_arguments = False
    positional_parameter_count = None
    keyword_parameter_names = []
    required_keyword_only_parameters = []
    accepts_extra_keywords = False
    has_default_parameters = False
    declared_return_type = None
    if chunk_type == "function":
        # 沿父指针找到文件级根节点，供self属性类型在整个文件范围内查找。
        syntax_root = node
        while syntax_root.parent is not None:
            syntax_root = syntax_root.parent
        code_calls = _code_calls(
            node, syntax_root, full_name,
            source_file.content.encode("utf-8")
        )
        parameter_info = _parameter_info(
            node, source_file.content.encode("utf-8")
        )
        parameter_count = parameter_info.total_count
        required_parameter_count = parameter_info.required_count
        accepts_extra_arguments = parameter_info.accepts_extra_arguments
        positional_parameter_count = parameter_info.positional_count
        keyword_parameter_names = parameter_info.keyword_names
        required_keyword_only_parameters = parameter_info.required_keyword_only_names
        accepts_extra_keywords = parameter_info.accepts_extra_keywords
        has_default_parameters = parameter_info.has_default_parameters
        return_type_node = node.child_by_field_name("return_type")
        if return_type_node is not None:
            declared_return_type = _node_text(return_type_node, source_file.content.encode("utf-8"))
    _append_chunk(chunks, source_file, chunk_type, content_start, content_end, full_name,
                  code_calls, extends_types, parameter_count,
                  required_parameter_count, accepts_extra_arguments,
                  positional_parameter_count, keyword_parameter_names,
                  required_keyword_only_parameters, accepts_extra_keywords,
                  has_default_parameters, declared_return_type)

    body = node.child_by_field_name("body")
    if body is not None:
        for child in body.named_children:
            _visit_node(child, source_file, chunks, [*parents, name])


def _code_calls(root: Node, syntax_root: Node, owner_full_name: str | None,
                source_bytes: bytes) -> list[CodeCall]:
    """读取函数中的调用名、行号、参数个数和可直接确认的接收者类型。"""

    calls = []
    pending = list(root.named_children)
    while pending:
        current = pending.pop()
        # 内层函数和类会生成自己的代码块，不把它们的调用算到外层函数。
        if current.type in {"function_definition", "class_definition"}:
            continue
        if current.type == "call":
            function_node = current.child_by_field_name("function")
            name = _called_name(function_node, source_bytes)
            if name:
                arguments_node = current.child_by_field_name("arguments")
                argument_count = 0
                positional_argument_count = 0
                keyword_argument_names = []
                has_argument_unpacking = False
                if arguments_node is not None:
                    argument_count = len(arguments_node.named_children)
                    for argument in arguments_node.named_children:
                        if argument.type == "keyword_argument":
                            name_node = argument.child_by_field_name("name")
                            if name_node is None:
                                name_node = argument.named_children[0]
                            keyword_argument_names.append(
                                _node_text(name_node, source_bytes)
                            )
                        elif argument.type in {"list_splat", "dictionary_splat"}:
                            has_argument_unpacking = True
                        else:
                            positional_argument_count += 1
                calls.append(CodeCall(
                    name=name,
                    line=current.start_point.row + 1,
                    receiver_type=_python_receiver_type(
                        function_node, root, syntax_root, owner_full_name, source_bytes
                    ),
                    argument_count=argument_count,
                    positional_argument_count=positional_argument_count,
                    keyword_argument_names=keyword_argument_names,
                    has_argument_unpacking=has_argument_unpacking,
                    **_python_return_method_lookup(
                        function_node, root, syntax_root,
                        owner_full_name, source_bytes
                    ),
                ))
        pending.extend(current.named_children)
    calls.sort(key=lambda call: (call.line, call.name))
    return calls


def _called_name(function_node: Node | None, source_bytes: bytes) -> str | None:
    if function_node is None:
        return None
    if function_node.type == "identifier":
        return _node_text(function_node, source_bytes)
    if function_node.type != "attribute":
        return None
    attribute_node = function_node.child_by_field_name("attribute")
    if attribute_node is not None:
        return _node_text(attribute_node, source_bytes)
    for child in reversed(function_node.named_children):
        if child.type == "identifier":
            return _node_text(child, source_bytes)
    return None


def _python_return_method_lookup(function_node, root, syntax_root,
                                 owner_full_name, source_bytes) -> dict:
    """外层调用的接收者若是方法调用，保存其返回类型查找条件。"""

    if function_node is None or function_node.type != "attribute":
        return {}
    receiver_call = function_node.child_by_field_name("object")
    if receiver_call is not None and receiver_call.type == "identifier":
        variable_name = _node_text(receiver_call, source_bytes)
        receiver_call = _assigned_value_before_call(
            variable_name, function_node, root, source_bytes
        )
    if receiver_call is None or receiver_call.type != "call":
        return {}
    receiver_function = receiver_call.child_by_field_name("function")
    if receiver_function is None or receiver_function.type != "attribute":
        return {}
    receiver_owner_type = _python_receiver_type(
        receiver_function, root, syntax_root, owner_full_name, source_bytes
    )
    receiver_method_name = _called_name(receiver_function, source_bytes)
    arguments_node = receiver_call.child_by_field_name("arguments")
    if receiver_owner_type is None or receiver_method_name is None:
        return {}
    argument_count = len(arguments_node.named_children) if arguments_node is not None else 0
    return {
        "receiver_method_owner_type": receiver_owner_type,
        "receiver_method_name": receiver_method_name,
        "receiver_method_argument_count": argument_count,
    }


def _assigned_value_before_call(variable_name: str, function_node: Node,
                                root: Node, source_bytes: bytes) -> Node | None:
    """查找同一函数顶层、当前调用之前对变量的最近一次直接赋值。"""

    body = root.child_by_field_name("body")
    if body is None:
        return None

    call_statement = function_node
    while call_statement.parent is not None and call_statement.parent != body:
        call_statement = call_statement.parent
    if call_statement.parent != body:
        return None

    latest_value = None
    for statement in body.named_children:
        if statement == call_statement:
            break
        assignment = statement
        if statement.type == "expression_statement" and statement.named_children:
            assignment = statement.named_children[0]
        if assignment.type != "assignment":
            if _node_assigns_variable(statement, variable_name, source_bytes):
                # 分支或循环里的赋值是否执行取决于运行时，不能继续沿用旧类型。
                latest_value = None
            continue
        left_node = assignment.child_by_field_name("left")
        if (
            left_node is not None
            and left_node.type == "identifier"
            and _node_text(left_node, source_bytes) == variable_name
        ):
            latest_value = assignment.child_by_field_name("right")
    return latest_value


def _node_assigns_variable(node: Node, variable_name: str,
                           source_bytes: bytes) -> bool:
    """判断复合语句内部是否可能给指定变量赋值。"""

    pending = list(node.named_children)
    while pending:
        current = pending.pop()
        # 内层函数和类有自己的局部范围，不影响当前函数变量。
        if current.type in {"function_definition", "class_definition"}:
            continue
        if current.type == "assignment":
            left_node = current.child_by_field_name("left")
            if (
                left_node is not None
                and left_node.type == "identifier"
                and _node_text(left_node, source_bytes) == variable_name
            ):
                return True
        pending.extend(current.named_children)
    return False


def _python_receiver_type(function_node: Node | None, root: Node, syntax_root: Node,
                          owner_full_name: str | None, source_bytes: bytes) -> str | None:
    """识别 ClassName.method 或 ClassName().method；普通变量的动态类型保持未知。"""

    if function_node is None or function_node.type != "attribute":
        return None
    object_node = function_node.child_by_field_name("object")
    if object_node is None:
        return None
    if object_node.type == "attribute":
        # self.xxx 或 cls.xxx：从所属类体内查找 xxx 的明确注解。
        inner_attribute = object_node.child_by_field_name("attribute")
        if inner_attribute is None:
            return None
        object_text = _node_text(inner_attribute, source_bytes)
        object_identifier = object_node.child_by_field_name("object")
        if (
            object_identifier is None
            or object_identifier.type != "identifier"
            or _node_text(object_identifier, source_bytes) not in {"self", "cls"}
            or owner_full_name is None
        ):
            return None
        # owner_full_name 是方法完整名，最后一段可能是方法名；
        # 所属类名需要去掉方法段（self/cls 只出现在类方法里）。
        owner_parts = owner_full_name.split(".")
        owner_class_name = (
            owner_parts[-2] if len(owner_parts) >= 2 else owner_parts[-1]
        )
        # 属性类型在类定义里查找，必须用文件级语法树而不是当前函数体。
        return _attribute_type(owner_class_name, object_text, syntax_root, source_bytes)
    if object_node.type == "identifier":
        object_text = _node_text(object_node, source_bytes)
        scope_node = root
        while scope_node is not None:
            for_element_type = _python_for_variable_type(
                object_text, scope_node, source_bytes,
            )
            if for_element_type is not None:
                return for_element_type
            declared_type = _declared_python_variable_type(
                object_text, scope_node, source_bytes,
            )
            if declared_type is not None:
                return declared_type
            # 词法作用域：嵌套函数沿函数链向上，类/模块边界停止。
            # 沿词法作用域向上：先跳出当前 body，再落到外层函数。
            parent = scope_node.parent
            if parent is None:
                scope_node = None
            elif parent.type == "function_definition":
                scope_node = parent
            elif parent.type == "block" and parent.parent is not None \
                    and parent.parent.type == "function_definition":
                scope_node = parent.parent
            else:
                scope_node = None
        if object_text and object_text[0].isupper():
            return object_text
        return None
    if object_node.type != "call":
        return None
    constructor_node = object_node.child_by_field_name("function")
    if constructor_node is None or constructor_node.type not in {"identifier", "attribute"}:
        return None
    constructor_name = _node_text(constructor_node, source_bytes)
    if constructor_name and constructor_name.rsplit(".", 1)[-1][0].isupper():
        return constructor_name
    return None


def _attribute_type(owner_full_name: str, attribute_name: str,
                    root: Node, source_bytes: bytes) -> str | None:
    """在所属类的 __init__ 中查找 self.xxx = 参数 的参数注解类型。"""

    owner_class = None
    for node in _iter_all(root):
        if node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            if name_node is not None and _node_text(name_node, source_bytes) == (
                owner_full_name.rsplit(".", 1)[-1]
            ):
                owner_class = node
                break
    if owner_class is None:
        return None
    constructor = None
    for node in _iter_all(owner_class):
        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node is not None and _node_text(name_node, source_bytes) == "__init__":
                constructor = node
                break
    if constructor is None:
        return None
    # self.xxx = 参数名；再从 __init__ 参数注解中找参数名的类型。
    parameter_types = {}
    parameters_node = constructor.child_by_field_name("parameters")
    if parameters_node is not None:
        for parameter in parameters_node.named_children:
            if parameter.type != "typed_parameter":
                continue
            # typed_parameter没有name/type字段；名称是子节点，类型包在type节点里。
            parameter_name = next(
                (child for child in parameter.named_children
                 if child.type == "identifier"), None
            )
            type_wrapper = parameter.child_by_field_name("type")
            parameter_type = None
            if type_wrapper is not None:
                parameter_type = next(
                    (child for child in type_wrapper.named_children
                     if child.type == "identifier"), type_wrapper
                )
            if parameter_name is None or parameter_type is None:
                continue
            parameter_types[
                _node_text(parameter_name, source_bytes)
            ] = _node_text(parameter_type, source_bytes)
    for node in _iter_all(constructor):
        if node.type != "assignment":
            continue
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")
        if (
            left_node is None or right_node is None
            or left_node.type != "attribute"
        ):
            continue
        left_name = left_node.child_by_field_name("attribute")
        left_object = left_node.child_by_field_name("object")
        if (
            left_name is None or left_object is None
            or _node_text(left_name, source_bytes) != attribute_name
            or left_object.type != "identifier"
            or _node_text(left_object, source_bytes) not in {"self", "cls"}
        ):
            continue
        parameter_name = _node_text(right_node, source_bytes)
        return parameter_types.get(parameter_name)
    return None


def _python_for_variable_type(variable_name: str, root: Node,
                              source_bytes: bytes) -> str | None:
    """for item in items：items 带 list[X] 注解时推断 item 为 X。

    只接受 list[...] 注解形式；裸 list 或 dict/自定义泛型不猜。
    """
    for node in _iter_all(root):
        if node.type != "for_statement":
            continue
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")
        if left_node is None or right_node is None:
            continue
        if _node_text(left_node, source_bytes) != variable_name:
            continue
        iterable_type = None
        if right_node.type == "identifier":
            # 可迭代对象可能是外层函数参数，沿函数链向上找注解。
            scope = root
            while scope is not None:
                iterable_type = _declared_python_variable_type(
                    _node_text(right_node, source_bytes), scope, source_bytes,
                )
                if iterable_type is not None:
                    break
                scope = (scope.parent
                         if scope.parent is not None
                         else None)
        if iterable_type is None or not iterable_type.startswith("list["):
            continue
        inner = iterable_type[len("list["):-1].split(",", 1)[0].strip()
        if inner and inner[0].isupper():
            return inner
    return None


def _declared_python_variable_type(variable_name: str, root: Node,
                                   source_bytes: bytes) -> str | None:
    """从函数参数注解或带注解赋值中读取变量类型。"""

    parameters_node = root.child_by_field_name("parameters")
    if parameters_node is not None:
        for parameter in parameters_node.named_children:
            if parameter.type not in {"typed_parameter", "typed_default_parameter"}:
                continue
            parameter_name = _parameter_name(parameter, source_bytes)
            type_node = parameter.child_by_field_name("type")
            if parameter_name == variable_name and type_node is not None:
                return _node_text(type_node, source_bytes)

    for node in _iter_all(root):
        if node.type != "assignment":
            continue
        left_node = node.child_by_field_name("left")
        type_node = node.child_by_field_name("type")
        if (
            left_node is None or type_node is None
            or left_node.type != "identifier"
            or _node_text(left_node, source_bytes) != variable_name
        ):
            continue
        return _node_text(type_node, source_bytes)
    return None


def _iter_all(root: Node):
    pending = [root]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(current.named_children)


def _node_text(node: Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8")


def _append_chunk(chunks, source_file, chunk_type, start_byte, end_byte, symbol_name,
                  code_calls=None, extends_types=None, parameter_count=None,
                  required_parameter_count=None, accepts_extra_arguments=False,
                  positional_parameter_count=None, keyword_parameter_names=None,
                  required_keyword_only_parameters=None,
                  accepts_extra_keywords=False,
                  has_default_parameters=False, declared_return_type=None):
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
        symbol_name=symbol_name, code_calls=code_calls or [],
        extends_types=extends_types or [],
        parameter_count=parameter_count,
        required_parameter_count=required_parameter_count,
        accepts_extra_arguments=accepts_extra_arguments,
        positional_parameter_count=positional_parameter_count,
        keyword_parameter_names=keyword_parameter_names or [],
        required_keyword_only_parameters=required_keyword_only_parameters or [],
        accepts_extra_keywords=accepts_extra_keywords,
        has_default_parameters=has_default_parameters,
        declared_return_type=declared_return_type,
    ))


def _parameter_info(node: Node, source_bytes: bytes) -> PythonParameterInfo:
    """统计 Python 调用允许的最少、最多参数和是否允许额外参数。

    类方法里的 self 和 cls 由 Python 自动传入，不计入调用者需要填写的参数。
    *args 可以接收额外位置参数；**kwargs 不会放宽位置参数个数。
    """

    parameters_node = node.child_by_field_name("parameters")
    if parameters_node is None:
        return PythonParameterInfo()
    info = PythonParameterInfo()
    parameters = parameters_node.named_children
    is_class_method = _is_class_method(node)
    keyword_only = False
    positional_only = any(
        child.type == "positional_separator" for child in parameters
    )
    for number, child in enumerate(parameters):
        parameter_name = _parameter_name(child, source_bytes)
        if is_class_method and number == 0 and parameter_name in {"self", "cls"}:
            continue
        if child.type == "positional_separator":
            positional_only = False
            continue
        if child.type == "keyword_separator":
            keyword_only = True
            positional_only = False
            continue
        if child.type in {"identifier", "typed_parameter"}:
            info.total_count += 1
            info.required_count += 1
            if keyword_only:
                info.required_keyword_only_names.append(parameter_name)
            else:
                info.positional_count += 1
            if not positional_only:
                info.keyword_names.append(parameter_name)
        if child.type in {"default_parameter", "typed_default_parameter"}:
            info.total_count += 1
            info.has_default_parameters = True
            if not keyword_only:
                info.positional_count += 1
            if not positional_only:
                info.keyword_names.append(parameter_name)
        if child.type == "list_splat_pattern":
            info.accepts_extra_arguments = True
            info.has_default_parameters = True
            keyword_only = True
            positional_only = False
        if child.type == "dictionary_splat_pattern":
            info.accepts_extra_keywords = True
            info.has_default_parameters = True
    return info


def _is_class_method(node: Node) -> bool:
    """确认函数外层最近的声明是类，而不是另一个函数。"""

    parent = node.parent
    while parent is not None:
        if parent.type == "class_definition":
            return True
        if parent.type == "function_definition":
            return False
        parent = parent.parent
    return False


def _parameter_name(node: Node, source_bytes: bytes) -> str | None:
    """读取普通参数或带类型参数的名字。"""

    if node.type == "identifier":
        return _node_text(node, source_bytes)
    for child in node.named_children:
        if child.type == "identifier":
            return _node_text(child, source_bytes)
    return None


def _superclass_types(node: Node, source_bytes: bytes) -> list[str]:
    """读取类声明的直接基类短名；对象导入路径由仓库汇总阶段解析。"""

    superclasses_node = node.child_by_field_name("superclasses")
    if superclasses_node is None:
        return []
    types = []
    for argument in superclasses_node.named_children:
        if argument.type == "identifier":
            types.append(source_bytes[argument.start_byte:argument.end_byte].decode("utf-8"))
        elif argument.type == "attribute":
            attribute_node = argument.child_by_field_name("attribute")
            if attribute_node is not None:
                types.append(source_bytes[attribute_node.start_byte:attribute_node.end_byte].decode("utf-8"))
    return types


def _top_level_declarations(root: Node) -> list[Node]:
    declarations = []
    for node in root.named_children:
        if node.type in {"class_definition", "function_definition", "decorated_definition"}:
            declarations.append(node)
    return declarations
