"""用仓库内全部成功代码块补全跨文件调用类型。"""

import ast
from dataclasses import replace
from pathlib import PurePosixPath
import re

from secval.models.code import CodeChunk


JAVA_TYPE_CHUNKS = {"class", "interface", "enum", "annotation", "record"}
TYPED_CALL_LANGUAGES = {"java", "javascript", "python", "typescript"}


def resolve_cross_file_calls(chunks: list[CodeChunk]) -> int:
    """按包名和import补全唯一可确认的类型，并返回补全数量。"""

    declared_types = _declared_types(chunks)
    file_contexts = _file_contexts(chunks)
    return_types = _collect_return_types(chunks, file_contexts, declared_types)
    resolved_supertypes = _resolve_supertypes(chunks, file_contexts, declared_types)
    ancestors = _ancestor_full_names(declared_types, resolved_supertypes)
    _attach_type_relations(chunks, resolved_supertypes, ancestors)
    return_types = _collect_return_types(chunks, file_contexts, declared_types)
    _propagate_inherited_methods(
        chunks, ancestors, return_types, file_contexts, declared_types
    )
    return_types = _merge_return_types(return_types, chunks)
    resolved_count = 0

    for chunk in chunks:
        if chunk.language.lower() not in TYPED_CALL_LANGUAGES:
            continue
        updated_calls = []
        for call in chunk.code_calls:
            updated_call = call
            returned_type = _return_type_for_call(
                call, chunk.relative_path, return_types, file_contexts, declared_types
            )
            if returned_type is not None:
                short_name, full_name = returned_type
                updated_call = replace(
                    call,
                    receiver_type=short_name,
                    receiver_type_full_name=full_name,
                )
            elif call.receiver_type is not None and call.receiver_type_full_name is None:
                full_name = _resolve_type_full_name(
                    call.receiver_type,
                    chunk.relative_path,
                    file_contexts,
                    declared_types,
                )
                if full_name is not None:
                    updated_call = replace(call, receiver_type_full_name=full_name)
            if updated_call != call:
                resolved_count += 1
            updated_calls.append(updated_call)
        chunk.code_calls = updated_calls
    return resolved_count


def _declared_types(chunks: list[CodeChunk]) -> set[str]:
    """收集仓库内声明类型；同名短类型在解析阶段按出现次数判断唯一性。"""

    declared = set()
    for chunk in chunks:
        if (
            chunk.language.lower() not in TYPED_CALL_LANGUAGES
            or chunk.chunk_type not in JAVA_TYPE_CHUNKS
        ):
            continue
        declared.update(chunk.symbol_names)
    return declared


def _count_type_declarations(chunks: list[CodeChunk]) -> dict[str, int]:
    """按短名统计类型声明次数；用于判断短名是否全局唯一。"""

    counts = {}
    for chunk in chunks:
        if (
            chunk.language.lower() not in TYPED_CALL_LANGUAGES
            or chunk.chunk_type not in JAVA_TYPE_CHUNKS
        ):
            continue
        for symbol_name in chunk.symbol_names:
            short_name = symbol_name.rsplit(".", 1)[-1]
            counts[short_name] = counts.get(short_name, 0) + 1
    return counts


def _resolve_supertypes(chunks, file_contexts, declared_types):
    """把每个类型块的父类型解析成完整名；保留显式extends/implements方向。"""

    resolved_supertypes = {}
    for chunk in chunks:
        if chunk.language.lower() not in {"java", "python", "typescript"}:
            continue
        if (
            chunk.chunk_type not in JAVA_TYPE_CHUNKS
            or len(chunk.symbol_names) != 1
            or chunk.symbol_names[0] in resolved_supertypes
        ):
            continue
        type_full_name = chunk.symbol_names[0]
        extends_full_names = []
        implements_full_names = []
        if chunk.language.lower() == "python" and chunk.chunk_type == "class":
            # Python统一用EXTENDS表达基类；优先按明确import和当前模块解析。
            for type_name in chunk.extends_types:
                full_name = _resolve_type_full_name(
                    type_name, chunk.relative_path, file_contexts, declared_types
                )
                if full_name is not None:
                    extends_full_names.append(full_name)
            if len(extends_full_names) != len(chunk.extends_types):
                # 有基类无法唯一确认时，整体保持未知，避免猜测继承方向。
                extends_full_names = []
        elif chunk.language.lower() in {"java", "typescript"}:
            for type_name in chunk.extends_types:
                full_name = _resolve_type_full_name(
                    type_name, chunk.relative_path, file_contexts, declared_types
                )
                if full_name is not None:
                    extends_full_names.append(full_name)
            for type_name in chunk.implements_types:
                full_name = _resolve_type_full_name(
                    type_name, chunk.relative_path, file_contexts, declared_types
                )
                if full_name is not None:
                    implements_full_names.append(full_name)
        else:
            continue
        resolved_supertypes[type_full_name] = {
            "extends": extends_full_names,
            "implements": implements_full_names,
        }
    for chunk in chunks:
        if chunk.language.lower() not in {"java", "python", "typescript"}:
            continue
        if chunk.chunk_type not in JAVA_TYPE_CHUNKS or len(chunk.symbol_names) != 1:
            continue
        relations = resolved_supertypes.get(chunk.symbol_names[0], {})
        chunk.extends_full_names = relations.get("extends", [])
    return resolved_supertypes


def _ancestor_full_names(declared_types, resolved_supertypes):
    """在仓库内已声明类型之间建立祖先闭包；外部类型只出现在直接层。"""

    ancestors = {}
    for type_full_name in declared_types:
        visiting = set()
        found = set()

        def visit(current):
            if current in visiting:
                return
            visiting.add(current)
            relations = resolved_supertypes.get(current, {})
            parents = relations.get("extends", []) + relations.get("implements", [])
            for parent in parents:
                if parent not in found:
                    found.add(parent)
                visit(parent)

        visit(type_full_name)
        ancestors[type_full_name] = found
    return ancestors


def _attach_type_relations(chunks, resolved_supertypes, ancestors):
    type_ancestors = {}
    for chunk in chunks:
        if (
            chunk.language.lower() not in {"java", "python", "typescript"}
            or chunk.chunk_type not in JAVA_TYPE_CHUNKS
        ):
            continue
        if len(chunk.symbol_names) != 1:
            continue
        type_full_name = chunk.symbol_names[0]
        relations = resolved_supertypes.get(type_full_name, {})
        chunk.supertype_full_names = (
            relations.get("extends", []) + relations.get("implements", [])
        )
        chunk.extends_full_names = list(relations.get("extends", []))
        chunk.ancestor_type_full_names = sorted(
            ancestors.get(type_full_name, set())
        )
        type_ancestors[type_full_name] = chunk.ancestor_type_full_names
    for chunk in chunks:
        method_chunk_type = (
            "function" if chunk.language.lower() == "python" else "method"
        )
        if (
            chunk.language.lower() not in {"java", "python", "typescript"}
            or chunk.chunk_type != method_chunk_type
        ):
            continue
        if len(chunk.symbol_names) != 1:
            continue
        owner_full_name = chunk.symbol_names[0].rsplit(".", 1)[0]
        chunk.ancestor_type_full_names = list(type_ancestors.get(owner_full_name, []))


def _file_contexts(chunks: list[CodeChunk]) -> dict[str, dict]:
    contexts = {}
    for chunk in chunks:
        if chunk.chunk_type != "file":
            continue
        if chunk.language.lower() == "python":
            contexts[chunk.relative_path] = _python_file_context(
                chunk.relative_path, chunk.content
            )
            continue
        if chunk.language.lower() in {"javascript", "typescript"}:
            contexts[chunk.relative_path] = _ecmascript_file_context(
                chunk.relative_path, chunk.content
            )
            continue
        if chunk.language.lower() != "java":
            continue
        package_match = re.search(
            r"^\s*package\s+([A-Za-z_$][A-Za-z0-9_$.]*)\s*;",
            chunk.content,
            re.MULTILINE,
        )
        package_name = package_match.group(1) if package_match else ""
        explicit_imports = {}
        wildcard_imports = set()
        imports = re.findall(
            r"^\s*import\s+(?!static\s)([A-Za-z_$][A-Za-z0-9_$.*]*)\s*;",
            chunk.content,
            re.MULTILINE,
        )
        for imported_name in imports:
            if imported_name.endswith(".*"):
                wildcard_imports.add(imported_name[:-2])
            else:
                explicit_imports[imported_name.rsplit(".", 1)[-1]] = imported_name
        contexts[chunk.relative_path] = {
            "package": package_name,
            "explicit_imports": explicit_imports,
            "wildcard_imports": wildcard_imports,
        }
    return contexts


def _ecmascript_file_context(relative_path: str, content: str) -> dict:
    """读取 JavaScript/TypeScript 的静态 ES Module 导入。"""

    module_name = _ecmascript_module_name(relative_path)
    require_aliases, require_imports = _ecmascript_require_imports(
        relative_path, content
    )
    explicit_imports = {}
    module_aliases = {}
    default_imports = {}
    import_pattern = re.compile(
        r"\bimport\s+(.+?)\s+from\s+['\"]([^'\"]+)['\"]\s*;?",
        re.MULTILINE,
    )
    for match in import_pattern.finditer(content):
        imported_values = match.group(1).strip()
        imported_module = _absolute_ecmascript_import(
            module_name, match.group(2)
        )
        if imported_module is None:
            continue
        namespace = re.fullmatch(
            r"\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)", imported_values
        )
        if namespace:
            module_aliases[namespace.group(1)] = imported_module
            continue
        # TypeScript类型语境不能可靠区分默认导出的类别，只有目标模块的默认导出
        # 恰好与仓库内唯一类型对应时才解析；歧义保持未知。
        if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", imported_values):
            default_imports[imported_values] = imported_module
            continue
        named = re.search(r"\{([^}]*)\}", imported_values)
        if named is None:
            continue
        for item in named.group(1).split(","):
            parts = re.split(r"\s+as\s+", item.strip())
            if not parts or not parts[0]:
                continue
            imported_name = parts[0]
            local_name = parts[1] if len(parts) == 2 else imported_name
            explicit_imports[local_name] = imported_module + "." + imported_name
    return {
        "package": module_name.rpartition(".")[0],
        "module": module_name,
        "explicit_imports": explicit_imports,
        "module_aliases": module_aliases,
        "require_imports": require_imports,
        "require_aliases": require_aliases,
        "default_imports": default_imports,
        "wildcard_imports": set(),
    }


def _ecmascript_module_name(relative_path: str) -> str:
    path = PurePosixPath(relative_path.replace("\\", "/"))
    parts = list(path.parts)
    parts[-1] = parts[-1].rsplit(".", 1)[0]
    return ".".join(parts)


def _absolute_ecmascript_import(module_name: str, imported_path: str) -> str | None:
    """把当前文件的相对导入路径换成项目内模块名。"""

    if not imported_path.startswith("."):
        return None
    base_parts = module_name.split(".")[:-1]
    for part in imported_path.replace("\\", "/").split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not base_parts:
                return None
            base_parts.pop()
            continue
        base_parts.append(part.rsplit(".", 1)[0])
    return ".".join(base_parts)


def _ecmascript_require_imports(relative_path: str, content: str):
    """读取CommonJS的const/let/var require导入。"""

    pattern = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)",
        re.MULTILINE,
    )
    module_aliases = {}
    for match in pattern.finditer(content):
        imported_module = _absolute_ecmascript_import(
            _ecmascript_module_name(relative_path), match.group(2)
        )
        if imported_module is not None:
            module_aliases[match.group(1)] = imported_module
    destructuring_pattern = re.compile(
        r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)",
        re.MULTILINE,
    )
    explicit_imports = {}
    for match in destructuring_pattern.finditer(content):
        imported_module = _absolute_ecmascript_import(
            _ecmascript_module_name(relative_path), match.group(2)
        )
        if imported_module is None:
            continue
        for item in match.group(1).split(","):
            parts = re.split(r":\s*", item.strip(), maxsplit=1)
            if not parts or not parts[0]:
                continue
            imported_name = parts[0].strip()
            local_name = parts[1].strip() if len(parts) == 2 else imported_name
            explicit_imports[local_name] = imported_module + "." + imported_name
    return module_aliases, explicit_imports


def _python_file_context(relative_path: str, content: str) -> dict:
    """读取Python模块名、显式导入和模块别名。"""

    module_name = _python_module_name(relative_path)
    package_name = module_name if relative_path.replace("\\", "/").endswith(
        "/__init__.py"
    ) else module_name.rpartition(".")[0]
    explicit_imports = {}
    module_aliases = {}
    try:
        tree = ast.parse(content)
    except SyntaxError:
        tree = ast.Module(body=[], type_ignores=[])
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local_name = alias.asname or alias.name.split(".", 1)[0]
                module_aliases[local_name] = alias.name
        if isinstance(statement, ast.ImportFrom):
            imported_module = _absolute_python_import(
                package_name, statement.module or "", statement.level
            )
            for alias in statement.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                imported_name = ".".join(
                    part for part in [imported_module, alias.name] if part
                )
                explicit_imports[local_name] = imported_name
                module_aliases[local_name] = imported_name
    return {
        "package": package_name,
        "module": module_name,
        "explicit_imports": explicit_imports,
        "module_aliases": module_aliases,
        "wildcard_imports": set(),
    }


def _python_module_name(relative_path: str) -> str:
    path = PurePosixPath(relative_path.replace("\\", "/"))
    parts = list(path.parts)
    stem = parts[-1].rsplit(".", 1)[0]
    if stem == "__init__":
        parts = parts[:-1]
    else:
        parts[-1] = stem
    return ".".join(parts)


def _absolute_python_import(package_name: str, module_name: str, level: int) -> str:
    if level == 0:
        return module_name
    package_parts = package_name.split(".") if package_name else []
    keep_count = max(0, len(package_parts) - level + 1)
    base_parts = package_parts[:keep_count]
    if module_name:
        base_parts.extend(module_name.split("."))
    return ".".join(base_parts)


def _collect_return_types(chunks, file_contexts, declared_types):
    return_types = {}
    for chunk in chunks:
        language = chunk.language.lower()
        expected_type = "method" if language == "java" else "function"
        if language not in {"java", "python"} or chunk.chunk_type != expected_type:
            continue
        if chunk.declared_return_type is None or len(chunk.symbol_names) != 1:
            continue
        return_full_name = _resolve_type_full_name(
            chunk.declared_return_type,
            chunk.relative_path,
            file_contexts,
            declared_types,
        )
        chunk.declared_return_full_name = return_full_name
        return_value = (chunk.declared_return_type, return_full_name)
        if language == "java":
            key = _method_key(chunk.symbol_names[0])
            if key is not None:
                return_types.setdefault(key, set()).add(return_value)
            continue
        if return_full_name is None:
            # Python短类型发生冲突时不把它用于链式调用，避免跨模块误连。
            continue
        if "." not in chunk.symbol_names[0]:
            continue
        owner, method_name = chunk.symbol_names[0].rsplit(".", 1)
        minimum = chunk.required_parameter_count or 0
        maximum = chunk.parameter_count or 0
        for argument_count in range(minimum, maximum + 1):
            return_types.setdefault(
                (owner, method_name, argument_count), set()
            ).add(return_value)
        if chunk.accepts_extra_arguments:
            return_types.setdefault(
                (owner, method_name, None), set()
            ).add(return_value)
    return return_types


def _propagate_inherited_methods(chunks, ancestors, return_types, file_contexts, declared_types):
    """子类未重新声明的方法沿用祖先的明确返回类型，供返回值链使用。"""

    for chunk in chunks:
        language = chunk.language.lower()
        if language not in {"java", "python"} or chunk.chunk_type not in JAVA_TYPE_CHUNKS:
            continue
        if len(chunk.symbol_names) != 1:
            continue
        type_full_name = chunk.symbol_names[0]
        ancestors_of_type = ancestors.get(type_full_name, set())
        declared_method_names = {
            other.symbol_names[0].split("(", 1)[0].rsplit(".", 1)[-1]
            for other in chunks
            if other.language.lower() == language
            and other.chunk_type == ("method" if language == "java" else "function")
            and len(other.symbol_names) == 1
            and other.symbol_names[0].rsplit(".", 1)[0] == type_full_name
        }
        # 只在子类型没有声明同名方法时，继承返回类型才登记到子类型名下。
        for ancestor in ancestors_of_type:
            for (owner, method_name, parameter_count), candidates in list(
                return_types.items()
            ):
                if owner != ancestor or method_name in declared_method_names:
                    continue
                if len(candidates) == 1:
                    short_name, full_name = next(iter(candidates))
                    inherited_key = (type_full_name, method_name, parameter_count)
                    return_types.setdefault(inherited_key, set()).add(
                        (short_name, full_name)
                    )


def _merge_return_types(return_types, chunks):
    """把继承登记的返回类型合并到返回值表；保持唯一结果才保留。"""

    merged = {}
    for key, candidates in return_types.items():
        if len(candidates) == 1:
            merged[key] = set(candidates)
    return merged


def _return_type_for_call(call, relative_path, return_types, file_contexts, declared_types):
    if call.receiver_method_owner_type is None:
        return None
    if call.receiver_method_name is None or call.receiver_method_argument_count is None:
        return None
    owner_full_name = _resolve_type_full_name(
        call.receiver_method_owner_type,
        relative_path,
        file_contexts,
        declared_types,
    )
    if owner_full_name is None:
        return None
    key = (
        owner_full_name,
        call.receiver_method_name,
        call.receiver_method_argument_count,
    )
    possible_types = return_types.get(key, set())
    if not possible_types:
        possible_types = return_types.get(
            (owner_full_name, call.receiver_method_name, None), set()
        )
    if len(possible_types) != 1:
        return None
    return next(iter(possible_types))


def _resolve_type_full_name(type_name, relative_path, file_contexts, declared_types):
    if type_name in declared_types:
        return type_name
    context = file_contexts.get(relative_path, {})
    alias, separator, rest = type_name.partition(".")
    aliased_prefix = context.get("module_aliases", {}).get(alias) or context.get(
        "require_aliases", {}
    ).get(alias)
    if aliased_prefix:
        aliased_name = aliased_prefix + (f".{rest}" if separator else "")
        if aliased_name in declared_types:
            return aliased_name
    if aliased_prefix and separator:
        module_matches = [
            full_name for full_name in declared_types
            if full_name.startswith(aliased_prefix + ".")
            and full_name.rsplit(".", 1)[-1] == rest.rsplit(".", 1)[-1]
        ]
        if len(module_matches) == 1:
            return module_matches[0]
        if len(module_matches) > 1:
            return None
    if not separator:
        # 默认导入有歧义：同一目标模块存在多个同名类型，或默认绑定本身不唯一。
        default_module = context.get("default_imports", {}).get(type_name)
        if default_module is None and aliased_prefix is not None:
            # require("./orders")整模块绑定也按默认导出的保守规则处理。
            default_module = aliased_prefix
        if default_module:
            module_matches = [
                full_name for full_name in declared_types
                if full_name.startswith(default_module + ".")
            ]
            # 默认导入的本地名通常不等于导出类型名；目标模块内只有一个声明类型时
            # 才能确认。模块声明多个类型时保持未知。
            if len(module_matches) == 1:
                return module_matches[0]
            return None
    short_name = type_name.rsplit(".", 1)[-1]
    # 解构require与命名import等价：按本地名找到目标模块成员。
    require_name = context.get("require_imports", {}).get(short_name)
    if require_name in declared_types:
        return require_name
    require_type_name = context.get("require_imports", {}).get(type_name)
    if require_type_name in declared_types:
        return require_type_name
    explicit_name = context.get("explicit_imports", {}).get(short_name)
    if explicit_name in declared_types:
        return explicit_name
    module_name = context.get("module", "")
    same_module_name = f"{module_name}.{short_name}" if module_name else short_name
    if same_module_name in declared_types:
        return same_module_name
    package_name = context.get("package", "")
    same_package_name = f"{package_name}.{short_name}" if package_name else short_name
    if same_package_name in declared_types:
        return same_package_name
    wildcard_matches = []
    for wildcard_package in context.get("wildcard_imports", set()):
        candidate = f"{wildcard_package}.{short_name}"
        if candidate in declared_types:
            wildcard_matches.append(candidate)
    if len(wildcard_matches) == 1:
        return wildcard_matches[0]
    global_matches = [
        full_name for full_name in declared_types
        if full_name.rsplit(".", 1)[-1] == short_name
    ]
    if len(global_matches) == 1:
        return global_matches[0]
    return None


def _method_key(full_name: str) -> tuple[str, str, int] | None:
    if "(" not in full_name or not full_name.endswith(")"):
        return None
    name_part, parameter_part = full_name.split("(", 1)
    if "." not in name_part:
        return None
    owner_full_name, method_name = name_part.rsplit(".", 1)
    return owner_full_name, method_name, _parameter_count(parameter_part[:-1])


def _parameter_count(parameter_text: str) -> int:
    if not parameter_text:
        return 0
    count = 1
    angle_depth = 0
    square_depth = 0
    for character in parameter_text:
        if character == "<":
            angle_depth += 1
        elif character == ">" and angle_depth > 0:
            angle_depth -= 1
        elif character == "[":
            square_depth += 1
        elif character == "]" and square_depth > 0:
            square_depth -= 1
        elif character == "," and angle_depth == 0 and square_depth == 0:
            count += 1
    return count
