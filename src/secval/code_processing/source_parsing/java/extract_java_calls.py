"""从 Java 语法树中提取方法调用引用，只用于生成关系线索。"""

from dataclasses import dataclass
import re

from tree_sitter import Node, Tree

from secval.models.code import SourceFile


@dataclass(frozen=True)
class JavaCallReference:
    """一次方法调用：所属符号、被调名称和源码位置。"""

    caller_full_name: str
    callee_name: str
    line: int
    receiver_type: str | None
    argument_count: int
    receiver_method_owner_type: str | None
    receiver_method_name: str | None
    receiver_method_argument_count: int | None


def extract_java_calls(source_file: SourceFile, syntax_tree: Tree) -> list[JavaCallReference]:
    """返回文件内全部 method_invocation 引用；这是静态线索，不是运行时事实。"""

    if source_file.language.lower() != "java":
        raise ValueError(f"Java 调用提取器不能处理此编程语言：{source_file.language}")
    # 直接用声明节点 ID 绑定完整名。这样两个同名重载方法不会互相覆盖。
    callers = {}
    symbol_nodes = _declared_symbol_nodes(source_file, syntax_tree)
    for item in symbol_nodes:
        if item.chunk_type in {
            "method",
            "constructor",
            "static_initializer",
            "initializer",
        }:
            callers[item.node.id] = (item.symbol.full_name, item.node)
    source_bytes = source_file.content.encode("utf-8")
    method_return_types, method_type_bounds = _method_return_types(symbol_nodes, source_bytes)
    references: list[JavaCallReference] = []
    _collect_calls(
        syntax_tree.root_node,
        None,
        callers,
        method_return_types,
        method_type_bounds,
        source_bytes,
        references,
    )
    return references


def _collect_calls(node: Node, current_caller, callers, method_return_types,
                   method_type_bounds, source_bytes: bytes,
                   references: list[JavaCallReference]) -> None:
    """深度优先收集调用；调用宿主按最近的声明节点确定。"""

    caller = current_caller
    if node.id in callers:
        caller = callers[node.id]
    if node.type == "method_invocation" and caller is not None:
        caller_full_name, caller_node = caller
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            arguments_node = node.child_by_field_name("arguments")
            receiver_type = _receiver_type(
                node,
                caller_full_name,
                caller_node,
                method_return_types,
                method_type_bounds,
                source_bytes,
            )
            receiver_method = _receiver_method_lookup(
                node,
                caller_full_name,
                caller_node,
                method_return_types,
                method_type_bounds,
                source_bytes,
            )
            references.append(JavaCallReference(
                caller_full_name=caller_full_name,
                callee_name=_text(name_node, source_bytes),
                line=node.start_point.row + 1,
                receiver_type=receiver_type,
                argument_count=(
                    len(arguments_node.named_children)
                    if arguments_node is not None
                    else 0
                ),
                receiver_method_owner_type=(receiver_method[0] if receiver_method else None),
                receiver_method_name=(receiver_method[1] if receiver_method else None),
                receiver_method_argument_count=(receiver_method[2] if receiver_method else None),
            ))
    for child_node in node.named_children:
        _collect_calls(
            child_node, caller, callers, method_return_types, method_type_bounds,
            source_bytes, references,
        )


def _text(node: Node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8")


def _receiver_type(node: Node, caller_full_name: str, caller_node: Node,
                   method_return_types, method_type_bounds,
                   source_bytes: bytes) -> str | None:
    """只识别可以直接确认的类型；普通变量名保持未知。"""

    object_node = node.child_by_field_name("object")
    owner_type = _caller_owner_type(caller_full_name)
    if object_node is None:
        # lambda 不创建新的 this；其中的隐式调用仍使用外围声明上下文。
        return owner_type
    object_text = _text(object_node, source_bytes).strip()
    if object_text == "this":
        return owner_type
    if object_text == "super":
        return None
    new_type = re.match(r"new\s+([A-Za-z_$][A-Za-z0-9_$.]*)", object_text)
    if new_type is not None:
        return new_type.group(1).rsplit(".", 1)[-1]
    if re.fullmatch(r"[A-Z][A-Za-z0-9_$]*(?:\.[A-Z][A-Za-z0-9_$]*)*", object_text):
        return object_text.rsplit(".", 1)[-1]
    if object_node.type == "identifier":
        return _declared_variable_type(
            object_text, node, caller_node, caller_full_name,
            method_return_types, method_type_bounds, source_bytes,
        )
    if object_node.type == "method_invocation":
        return _method_call_return_type(
            object_node,
            caller_full_name,
            caller_node,
            method_return_types,
            method_type_bounds,
            source_bytes,
        )
    return None


def _method_return_types(symbol_nodes, source_bytes: bytes):
    """建立同一文件内的“所属类型、方法名、参数个数 -> 返回类型”表。"""

    return_types: dict[tuple[str, str, int], set[str]] = {}
    bound_types: dict[tuple[str, str, int], dict[str, str]] = {}
    for item in symbol_nodes:
        if item.node.type != "method_declaration":
            continue
        return_node = item.node.child_by_field_name("type")
        name_node = item.node.child_by_field_name("name")
        parameters_node = item.node.child_by_field_name("parameters")
        if return_node is None or name_node is None:
            continue
        owner_type = _caller_owner_type(item.symbol.full_name)
        return_type_text = _text(return_node, source_bytes)
        if owner_type is None or not return_type_text:
            continue
        # 记录类型变量到上界的映射，例如 <T extends Processor> 时 T -> Processor。
        type_bounds: dict[str, str] = {}
        type_parameters_node = item.node.child_by_field_name("type_parameters")
        if type_parameters_node is not None:
            for type_parameter in type_parameters_node.named_children:
                if type_parameter.type != "type_parameter":
                    continue
                children = type_parameter.named_children
                if not children:
                    continue
                variable_name = _text(children[0], source_bytes)
                bound_text = None
                for child in children[1:]:
                    if child.type == "type_bound":
                        bound_text = _text(child, source_bytes)
                        break
                if bound_text is None:
                    continue
                # type_bound 文本形如 "extends Processor"，取第一个上界。
                bound_parts = bound_text.split(None, 1)
                if len(bound_parts) < 2:
                    continue
                first_bound = read_simple_java_type(bound_parts[1])
                if first_bound is not None:
                    type_bounds[variable_name] = first_bound
        parameter_count = 0
        if parameters_node is not None:
            parameter_count = len([
                child for child in parameters_node.named_children
                if child.type in {"formal_parameter", "spread_parameter"}
            ])
        key = (owner_type, _text(name_node, source_bytes), parameter_count)
        # 每个声明先替换自己的上界，再合并候选。不能让后一个重载的
        # T 上界覆盖前一个重载；参数个数相同不足以确定具体重载。
        resolved_type = type_bounds.get(return_type_text, return_type_text)
        return_types.setdefault(key, set()).add(resolved_type)
    return return_types, bound_types


def _method_call_return_type(node: Node, caller_full_name: str, caller_node: Node,
                             method_return_types, method_type_bounds,
                             source_bytes: bytes) -> str | None:
    """解析一层方法返回值；同一签名出现不同返回类型时保持未知。"""

    name_node = node.child_by_field_name("name")
    if name_node is None:
        return None
    arguments_node = node.child_by_field_name("arguments")
    argument_count = len(arguments_node.named_children) if arguments_node is not None else 0
    owner_type = _receiver_type(
        node, caller_full_name, caller_node, method_return_types,
        method_type_bounds, source_bytes,
    )
    if owner_type is None:
        return None
    key = (owner_type, _text(name_node, source_bytes), argument_count)
    possible_types = method_return_types.get(key, set())
    if len(possible_types) != 1:
        return None
    # 泛型方法返回类型变量：例如 <T extends Processor> T pick() 中 T 已在
    # 声明处绑定上界，调用处返回类型按上界解析。
    return_type_text = next(iter(possible_types))
    bounds_for_key = method_type_bounds.get(key, {})
    if return_type_text in bounds_for_key:
        return bounds_for_key[return_type_text]
    return read_simple_java_type(return_type_text)


def _receiver_method_lookup(node: Node, caller_full_name: str, caller_node: Node,
                            method_return_types, method_type_bounds,
                            source_bytes: bytes):
    """返回外层调用接收者所对应的方法查找条件。"""

    receiver_call = node.child_by_field_name("object")
    if receiver_call is None or receiver_call.type != "method_invocation":
        return None
    name_node = receiver_call.child_by_field_name("name")
    if name_node is None:
        return None
    owner_type = _receiver_type(
        receiver_call, caller_full_name, caller_node, method_return_types,
        method_type_bounds, source_bytes,
    )
    if owner_type is None:
        return None
    arguments_node = receiver_call.child_by_field_name("arguments")
    argument_count = len(arguments_node.named_children) if arguments_node is not None else 0
    return owner_type, _text(name_node, source_bytes), argument_count


def _caller_owner_type(caller_full_name: str) -> str | None:
    name_without_parameters = caller_full_name.split("(", 1)[0]
    if "." not in name_without_parameters:
        return None
    owner_name = name_without_parameters.rsplit(".", 1)[0]
    return owner_name.rsplit(".", 1)[-1]


def _declared_variable_type(variable_name: str, call_node: Node, caller_node: Node,
                            caller_full_name: str, method_return_types,
                            method_type_bounds, source_bytes: bytes) -> str | None:
    """按局部变量、参数、字段的遮蔽顺序查找明确声明类型。"""

    local_found, local_type = _local_variable_type(
        variable_name, call_node, caller_node, caller_full_name,
        method_return_types, method_type_bounds, source_bytes,
    )
    if local_found:
        return local_type
    parameter_found, parameter_type = _parameter_type(
        variable_name, caller_node, source_bytes
    )
    if parameter_found:
        return parameter_type
    return _field_type(variable_name, caller_node, source_bytes)


def _local_variable_type(variable_name: str, call_node: Node, caller_node: Node,
                         caller_full_name: str, method_return_types,
                         method_type_bounds, source_bytes: bytes) -> tuple[bool, str | None]:
    ancestor_distance = {}
    current = call_node
    distance = 0
    while current is not None:
        ancestor_distance[current.id] = distance
        if current.id == caller_node.id:
            break
        current = current.parent
        distance += 1

    candidates = []
    pending = [caller_node]
    while pending:
        current = pending.pop()
        if current.id != caller_node.id and current.type in {
            "method_declaration", "constructor_declaration", "class_declaration",
            "interface_declaration", "enum_declaration", "record_declaration",
        }:
            continue
        variable_declaration_types = {
            "local_variable_declaration",
            "enhanced_for_statement",
            "resource",
            "catch_formal_parameter",
        }
        if current.type in variable_declaration_types and current.start_byte < call_node.start_byte:
            scope = _nearest_variable_scope(current, caller_node)
            if scope.id in ancestor_distance:
                if current.type == "local_variable_declaration":
                    found, declared_type = _type_for_declarator(
                        current, variable_name, source_bytes, caller_full_name,
                        caller_node, method_return_types, method_type_bounds,
                        lookup_node=call_node,
                    )
                else:
                    found, declared_type = _direct_variable_type(
                        current, variable_name, source_bytes
                    )
                if found:
                    candidates.append((ancestor_distance[scope.id], -current.start_byte,
                                       declared_type))
        pending.extend(current.named_children)
    if not candidates:
        return False, None
    candidates.sort()
    return True, candidates[0][2]


def _nearest_variable_scope(node: Node, caller_node: Node) -> Node:
    scope_types = {
        "block", "for_statement", "enhanced_for_statement", "catch_clause",
        "try_with_resources_statement", "switch_block", "lambda_expression",
    }
    if node.type == "enhanced_for_statement":
        return node
    current = node.parent
    while current is not None and current.id != caller_node.id:
        if current.type in scope_types:
            return current
        current = current.parent
    return caller_node


def _parameter_type(variable_name: str, caller_node: Node,
                    source_bytes: bytes) -> tuple[bool, str | None]:
    parameters = caller_node.child_by_field_name("parameters")
    if parameters is None:
        return False, None
    pending = list(parameters.named_children)
    while pending:
        parameter = pending.pop()
        name_node = parameter.child_by_field_name("name")
        type_node = parameter.child_by_field_name("type")
        if name_node is not None and type_node is not None:
            if _text(name_node, source_bytes) == variable_name:
                return True, read_simple_java_type(_text(type_node, source_bytes))
        pending.extend(parameter.named_children)
    return False, None


def _field_type(variable_name: str, caller_node: Node,
                source_bytes: bytes) -> str | None:
    owner = caller_node.parent
    while owner is not None and owner.type not in {
        "class_declaration", "interface_declaration", "enum_declaration",
        "record_declaration", "annotation_type_declaration",
    }:
        owner = owner.parent
    if owner is None:
        return None
    body = owner.child_by_field_name("body")
    if body is None:
        return None
    for child in body.named_children:
        if child.type not in {"field_declaration", "constant_declaration"}:
            continue
        found, declared_type = _type_for_declarator(child, variable_name, source_bytes)
        if found:
            return declared_type
    return None


def _type_for_declarator(declaration: Node, variable_name: str,
                         source_bytes: bytes, caller_full_name: str | None = None,
                         caller_node: Node | None = None, method_return_types=None,
                         method_type_bounds=None, lookup_node: Node | None = None) -> tuple[bool, str | None]:
    type_node = declaration.child_by_field_name("type")
    if type_node is None:
        return False, None
    for declarator in declaration.children_by_field_name("declarator"):
        name_node = declarator.child_by_field_name("name")
        if name_node is not None and _text(name_node, source_bytes) == variable_name:
            declared_type = read_simple_java_type(_text(type_node, source_bytes))
            # var 推断：语法树已给出 cast 目标类型时直接采用，例如
            # `var r = (Runnable)() -> run();`，这是从节点就能读出的事实。
            if declared_type is None and _text(type_node, source_bytes).strip() == "var":
                # 初始化表达式内部不能再通过同一个变量的初始化式推断类型。
                # 保留“已找到但类型未知”，也避免错误回退到同名字段。
                if lookup_node is not None and (
                    declarator.start_byte <= lookup_node.start_byte < declarator.end_byte
                ):
                    return True, None
                cast_type = _cast_expression_type(declarator, source_bytes)
                if cast_type is not None:
                    return True, cast_type
                new_type = _object_creation_type(declarator, source_bytes)
                if new_type is not None:
                    return True, new_type
                if caller_full_name is not None and caller_node is not None:
                    method_type = _declarator_method_return_type(
                        declarator, caller_full_name, caller_node,
                        method_return_types, method_type_bounds, source_bytes,
                    )
                    if method_type is not None:
                        return True, method_type
            return True, declared_type
    return False, None


def _declarator_method_return_type(declarator: Node, caller_full_name: str,
                                   caller_node: Node, method_return_types,
                                   method_type_bounds,
                                   source_bytes: bytes) -> str | None:
    """var 右值是方法调用时，用方法返回类型表解析变量类型。"""
    for child in declarator.named_children:
        if child.type == "method_invocation":
            return _method_call_return_type(
                child, caller_full_name, caller_node,
                method_return_types, method_type_bounds, source_bytes,
            )
    return None

def _object_creation_type(declarator: Node, source_bytes: bytes) -> str | None:
    """从 var x = new T(...) 读出 T。"""
    for child in declarator.named_children:
        if child.type == "object_creation_expression":
            type_node = child.child_by_field_name("type")
            if type_node is not None:
                return read_simple_java_type(_text(type_node, source_bytes))
    return None

def _direct_variable_type(declaration: Node, variable_name: str,
                          source_bytes: bytes) -> tuple[bool, str | None]:
    """读取增强for、资源和catch参数直接携带的名称及类型。"""

    name_node = declaration.child_by_field_name("name")
    if name_node is None or _text(name_node, source_bytes) != variable_name:
        return False, None
    type_node = declaration.child_by_field_name("type")
    # 增强for 用 var 时，元素类型按可迭代对象的泛型实参解析，
    # 例如 `for (var p : items)` 中 items 是 List<Processor> 时 p 是 Processor。
    if (
        declaration.type == "enhanced_for_statement"
        and type_node is not None
        and _text(type_node, source_bytes).strip() == "var"
    ):
        return True, _enhanced_for_var_element_type(declaration, source_bytes)
    if type_node is None and declaration.type == "catch_formal_parameter":
        for child in declaration.named_children:
            if child.type == "catch_type":
                type_node = child
                break
    if type_node is None:
        return True, None
    return True, read_simple_java_type(_text(type_node, source_bytes))


def _enhanced_for_var_element_type(declaration: Node, source_bytes: bytes) -> str | None:
    """从增强for的可迭代对象读 var 元素类型，只处理能直接读出的情形。"""
    value_node = declaration.child_by_field_name("value")
    if value_node is None:
        return None
    value_text = _text(value_node, source_bytes).strip()
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value_text):
        # 可迭代对象是变量时，沿遮蔽顺序找它的声明类型带泛型文本。
        iterable_type_text = _declared_variable_type_text(
            value_text, declaration, source_bytes,
        )
    else:
        iterable_type_text = None
    if iterable_type_text is None:
        return None
    if iterable_type_text.endswith("[]"):
        element_text = iterable_type_text[:-2].strip()
        # 多维数组的元素仍是数组，不能误连到最内层对象的方法。
        if element_text.endswith("[]"):
            return None
        return read_simple_java_type(element_text)
    # 任意泛型类型的第一个参数不一定是迭代元素，只接受明确的标准接口。
    container = iterable_type_text.split("<", 1)[0].strip()
    if "." not in container:
        container = _explicit_import_type(container, declaration, source_bytes) or container
    if container not in {"java.util.List", "java.util.Set", "java.util.Collection",
                         "java.lang.Iterable"}:
        # 自定义容器只有同文件直接 implements Iterable<X> 才按元素类型推断；
        # 泛型转发、间接继承等不做猜测。
        return _directly_iterable_element_type(container, declaration, source_bytes)
    return read_generic_type_argument(iterable_type_text)


def _directly_iterable_element_type(container_text: str, node: Node,
                                    source_bytes: bytes) -> str | None:
    """在同文件沿继承链查 implements Iterable<X>；泛型上界或找不到则放弃。

    子类本身没实现 Iterable 时向上找父类；父类用类型变量实现 Iterable
    （如 Box<T> implements Iterable<T>）需要类型实参替换，这里不猜。
    visited 防止同文件循环继承导致死循环。
    """
    root = node
    while root.parent is not None:
        root = root.parent
    visited = set()
    current_name = container_text.rsplit(".", 1)[-1]
    while current_name is not None and current_name not in visited:
        visited.add(current_name)
        class_node = _top_level_class_by_name(root, current_name, source_bytes)
        if class_node is None:
            return None
        interfaces_node = class_node.child_by_field_name("interfaces")
        if interfaces_node is not None:
            for candidate in interfaces_node.named_children:
                candidate_text = _text(candidate, source_bytes)
                base = candidate_text.split("<", 1)[0].strip()
                if base in {"java.lang.Iterable", "Iterable"}:
                    # 类型变量或通配符实参在这里返回 None，不向上继续。
                    return read_generic_type_argument(candidate_text)
        superclass_node = class_node.child_by_field_name("superclass")
        if superclass_node is None:
            return None
        superclass_text = _text(superclass_node, source_bytes)
        # superclass 节点文本形如 "extends Base<Item>"，去掉前缀取短名。
        superclass_name = superclass_text[len("extends"):].split("<", 1)[0].strip()
        current_name = superclass_name.rsplit(".", 1)[-1]
    return None


def _top_level_class_by_name(root: Node, class_name: str,
                             source_bytes: bytes) -> Node | None:
    for type_node in root.named_children:
        if type_node.type != "class_declaration":
            continue
        name_node = type_node.child_by_field_name("name")
        if name_node is not None and _text(name_node, source_bytes) == class_name:
            return type_node
    return None


def _explicit_import_type(short_name: str, node: Node, source_bytes: bytes) -> str | None:
    """只采用唯一显式类型导入；文件内同名类型或类型参数出现时保持未知。"""
    root = node
    while root.parent is not None:
        root = root.parent
    pending = [root]
    while pending:
        current = pending.pop()
        if current.type in {"class_declaration", "interface_declaration", "enum_declaration",
                            "record_declaration", "annotation_type_declaration", "type_parameter"}:
            name = current.child_by_field_name("name")
            if name is None and current.type == "type_parameter" and current.named_children:
                name = current.named_children[0]
            if name is not None and _text(name, source_bytes) == short_name:
                return None
        pending.extend(current.named_children)
    imported_types = set()
    for child in root.named_children:
        if child.type != "import_declaration":
            continue
        import_text = _text(child, source_bytes)
        match = re.fullmatch(r"import\s+([\w.]+)\s*;", import_text.strip())
        if match is not None and match.group(1).rsplit(".", 1)[-1] == short_name:
            imported_types.add(match.group(1))
    if len(imported_types) == 1:
        return next(iter(imported_types))
    return None


def _declared_variable_type_text(variable_name: str, from_node: Node,
                                 source_bytes: bytes) -> str | None:
    """向上查变量声明，返回带泛型的完整类型文本（与短名推断互补）。"""
    current = from_node.parent
    while current is not None:
        if current.type == "block":
            # 只查当前块中使用点之前的直接声明，不能读到兄弟块的局部变量。
            for child in reversed(current.named_children):
                if child.start_byte >= from_node.start_byte:
                    continue
                if child.type == "local_variable_declaration":
                    found, type_text = _type_text_for_declarator(
                        child, variable_name, source_bytes,
                    )
                    if found:
                        return type_text
        if current.type == "enhanced_for_statement":
            name = current.child_by_field_name("name")
            if name is not None and _text(name, source_bytes) == variable_name:
                type_node = current.child_by_field_name("type")
                return _text(type_node, source_bytes) if type_node is not None else None
        if current.type == "for_statement":
            for child in current.named_children:
                if child.type == "local_variable_declaration":
                    found, type_text = _type_text_for_declarator(child, variable_name, source_bytes)
                    if found:
                        return type_text
        parameters = current.child_by_field_name("parameters")
        if parameters is not None:
            for parameter in parameters.named_children:
                name = parameter.child_by_field_name("name")
                if name is not None and _text(name, source_bytes) == variable_name:
                    type_node = parameter.child_by_field_name("type")
                    if type_node is None:
                        return None
                    return _text(type_node, source_bytes) + _extra_array_dimensions(parameter, source_bytes)
        if current.type in {
            "class_declaration", "interface_declaration", "enum_declaration", "record_declaration",
        }:
            body = current.child_by_field_name("body")
            if body is not None:
                for child in body.named_children:
                    if child.type in {"field_declaration", "constant_declaration"}:
                        found, type_text = _type_text_for_declarator(child, variable_name, source_bytes)
                        if found:
                            return type_text
            return None
        if current.type == "local_variable_declaration":
            found, type_text = _type_text_for_declarator(
                current, variable_name, source_bytes,
            )
            if found:
                return type_text
        if current.type == "formal_parameter":
            name_node = current.child_by_field_name("name")
            type_node = current.child_by_field_name("type")
            if (
                name_node is not None
                and type_node is not None
                and _text(name_node, source_bytes) == variable_name
            ):
                return _text(type_node, source_bytes)
        current = current.parent
    return None


def _type_text_for_declarator(declaration: Node, variable_name: str,
                              source_bytes: bytes) -> tuple[bool, str | None]:
    """返回声明里变量对应的原始类型文本，不做短名过滤。"""
    type_node = declaration.child_by_field_name("type")
    if type_node is None:
        return False, None
    for declarator in declaration.children_by_field_name("declarator"):
        name_node = declarator.child_by_field_name("name")
        if name_node is not None and _text(name_node, source_bytes) == variable_name:
            return True, _text(type_node, source_bytes) + _extra_array_dimensions(declarator, source_bytes)
    return False, None


def _extra_array_dimensions(node: Node, source_bytes: bytes) -> str:
    """读取变量名之后的数组维度；类型节点中的维度由调用方保留。"""
    for child in node.named_children:
        if child.type == "dimensions":
            return "[]" * _text(child, source_bytes).count("[")
    return ""

def read_simple_java_type(type_text: str) -> str | None:
    """从明确类型声明中取最外层短类型名；var和常见类型变量保持未知。"""

    without_generics = type_text.split("<", 1)[0]
    without_arrays = without_generics.replace("[]", "").strip()
    short_name = without_arrays.rsplit(".", 1)[-1]
    if short_name in {
        "var", "boolean", "byte", "short", "int", "long",
        "float", "double", "char",
    } or re.fullmatch(r"[TEKVR]", short_name):
        return None
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", short_name):
        return None
    return short_name


def read_generic_type_argument(type_text: str) -> str | None:
    """从类型文本取第一个泛型实参的短名，例如 List<Processor> 返回 Processor。

    嵌套泛型（如 List<Map<String, User>>）取最外层第一个实参的完整文本
    再截短名；上界通配符可读出上界，下界通配符不能当作元素的确定类型。
    """
    start = type_text.find("<")
    if start == -1:
        return None
    depth = 0
    end = -1
    for index in range(start, len(type_text)):
        if type_text[index] == "<":
            depth += 1
        elif type_text[index] == ">":
            depth -= 1
        if depth == 0:
            end = index
            break
    if end == -1:
        return None
    arguments_text = type_text[start + 1:end]
    depth = 0
    first_end = len(arguments_text)
    for index, character in enumerate(arguments_text):
        if character == "<":
            depth += 1
        elif character == ">":
            depth -= 1
        elif character == "," and depth == 0:
            first_end = index
            break
    argument = arguments_text[:first_end].strip()
    upper_bound = re.fullmatch(r"\?\s+extends\s+(.+)", argument)
    if upper_bound is not None:
        argument = upper_bound.group(1).strip()
    if not argument or argument.startswith("?"):
        return None
    # Item[] 是数组对象，不能将其方法归属误写为 Item。
    if argument.endswith("]"):
        return None
    return read_simple_java_type(argument)


def _cast_expression_type(declarator: Node, source_bytes: bytes) -> str | None:
    """从 `var x = (T) ...` 的强制类型转换中读出 T。

    只接受 cast 的值是 lambda 或方法引用的情形，例如
    `var r = (Runnable)() -> run();`。如果值是普通字符串或其它对象，
    直接 cast 出的类型可能是窄化或无关转换，不应作为接收者类型。
    """

    for child in declarator.named_children:
        if child.type == "cast_expression":
            value_node = child.child_by_field_name("value")
            if value_node is None or value_node.type not in (
                "lambda_expression",
                "method_reference",
            ):
                return None
            type_node = child.child_by_field_name("type")
            if type_node is not None and type_node.type == "type_identifier":
                return read_simple_java_type(_text(type_node, source_bytes))
    return None

def _declared_symbol_nodes(source_file, syntax_tree):
    """延迟导入避免循环依赖，并返回带语法节点的符号。"""

    from secval.code_processing.source_parsing.java.extract_java_symbols import (
        extract_java_symbol_nodes,
    )
    return extract_java_symbol_nodes(source_file, syntax_tree)
