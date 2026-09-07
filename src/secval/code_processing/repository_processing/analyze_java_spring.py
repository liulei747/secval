"""从固定Java源码中提取无需运行应用即可确定的Spring语义。"""

import re

_COMPONENT = re.compile(r"@(Component|Service|Repository|Controller|RestController)\b(?:\s*\(\s*[\"']([^\"']+)[\"']\s*\))?")
_QUALIFIER = re.compile(r"@(Qualifier|Resource)\s*\(\s*(?:name\s*=\s*)?[\"']([^\"']+)[\"']")
_FIELD_TYPE = re.compile(r"\b(?:private|protected|public)\s+(?:final\s+)?([\w.$<>?, ]+)\s+\w+\s*(?:[;=])")
_INJECTION_MARKERS = ("@Autowired", "@Inject", "@Resource")
_ENTRY_MARKERS = {
    "GetMapping": "HTTP_ROUTE", "PostMapping": "HTTP_ROUTE",
    "PutMapping": "HTTP_ROUTE", "DeleteMapping": "HTTP_ROUTE",
    "PatchMapping": "HTTP_ROUTE", "RequestMapping": "HTTP_ROUTE",
    "Scheduled": "SCHEDULED", "EventListener": "EVENT_LISTENER",
    "KafkaListener": "MESSAGE_CONSUMER", "RabbitListener": "MESSAGE_CONSUMER",
    "JmsListener": "MESSAGE_CONSUMER", "Async": "ASYNC_ENTRY",
}


def analyze_java_spring(chunks):
    """返回Bean、注入候选和框架入口；不猜测条件配置的唯一运行时结果。"""
    java_chunks = [chunk for chunk in chunks if chunk.language.lower() == "java"]
    type_chunks = [chunk for chunk in java_chunks if chunk.chunk_type in {"class", "record", "enum"}
                   and len(chunk.symbol_ids) == 1]
    beans = []
    for chunk in type_chunks:
        full_name = chunk.symbol_names[0]
        component = _COMPONENT.search(chunk.content)
        if component:
            beans.append({
                "symbol_id": str(chunk.symbol_ids[0]), "type_full_name": full_name,
                "bean_name": component.group(2) or _default_bean_name(full_name),
                "stereotype": component.group(1),
                "primary": "@Primary" in chunk.content,
                "qualifiers": [value for _, value in _QUALIFIER.findall(chunk.content)],
                "conditional": any(value in chunk.content for value in ("@Profile", "@Conditional")),
            })
    for chunk in java_chunks:
        if chunk.chunk_type != "method" or len(chunk.symbol_ids) != 1 or "@Bean" not in chunk.content:
            continue
        bean_annotation = re.search(r"@Bean\b(?:\s*\(([^)]*)\))?", chunk.content)
        bean_name = _annotation_value(bean_annotation.group(1)) if bean_annotation else None
        return_type = chunk.declared_return_full_name or chunk.declared_return_type
        if return_type:
            beans.append({
                "symbol_id": str(chunk.symbol_ids[0]), "type_full_name": return_type,
                "bean_name": bean_name or chunk.symbol_names[0].split("(", 1)[0].rsplit(".", 1)[-1],
                "stereotype": "Bean", "primary": "@Primary" in chunk.content,
                "qualifiers": [value for _, value in _QUALIFIER.findall(chunk.content)],
                "conditional": any(value in chunk.content for value in ("@Profile", "@Conditional")),
            })

    bean_by_type = {}
    for bean in beans:
        names = {bean["type_full_name"], bean["type_full_name"].rsplit(".", 1)[-1]}
        chunk = next((item for item in type_chunks if str(item.symbol_ids[0]) == bean["symbol_id"]), None)
        if chunk is not None:
            names.update(chunk.supertype_full_names)
            names.update(value.rsplit(".", 1)[-1] for value in chunk.supertype_full_names)
        for name in names:
            bean_by_type.setdefault(name, []).append(bean)

    injections = []
    for chunk in java_chunks:
        if chunk.chunk_type not in {"field", "constant"} or len(chunk.symbol_ids) != 1:
            continue
        if not any(marker in chunk.content for marker in _INJECTION_MARKERS):
            continue
        match = _FIELD_TYPE.search(chunk.content)
        if not match:
            continue
        requested_type = _erase_type(match.group(1))
        qualifier = next((value for _, value in _QUALIFIER.findall(chunk.content)), None)
        injections.append(_injection(
            str(chunk.symbol_ids[0]), "FIELD", requested_type, qualifier,
            bean_by_type,
        ))

    callables = [chunk for chunk in java_chunks
                 if chunk.chunk_type in {"method", "constructor"}
                 and len(chunk.symbol_ids) == 1]
    constructors_by_owner = {}
    for chunk in callables:
        if chunk.chunk_type == "constructor":
            constructors_by_owner.setdefault(_callable_owner(chunk), []).append(chunk)
    component_types = {bean["type_full_name"] for bean in beans
                       if bean["stereotype"] != "Bean"}
    field_ids = {chunk.symbol_names[0]: str(chunk.symbol_ids[0]) for chunk in java_chunks
                 if chunk.chunk_type in {"field", "constant"} and len(chunk.symbol_ids) == 1}
    for chunk in callables:
        explicitly_injected = any(marker in chunk.content for marker in _INJECTION_MARKERS)
        owner = _callable_owner(chunk)
        implicitly_injected = (chunk.chunk_type == "constructor"
                               and owner in component_types
                               and len(constructors_by_owner.get(owner, [])) == 1)
        if not explicitly_injected and not implicitly_injected:
            continue
        annotation_prefix = chunk.content.split(
            chunk.symbol_names[0].split("(", 1)[0].rsplit(".", 1)[-1], 1
        )[0]
        callable_qualifier = next(
            (value for _, value in _QUALIFIER.findall(annotation_prefix)), None
        )
        for index, parameter in enumerate(_parameters(chunk)):
            qualifier = parameter["qualifier"] or callable_qualifier
            injection = _injection(
                str(chunk.symbol_ids[0]),
                "CONSTRUCTOR_PARAMETER" if chunk.chunk_type == "constructor"
                else "METHOD_PARAMETER",
                parameter["type"], qualifier, bean_by_type,
                parameter_index=index, parameter_name=parameter["name"],
            )
            assigned = re.search(
                rf"\bthis\s*\.\s*(\w+)\s*=\s*{re.escape(parameter['name'])}\s*;",
                chunk.content,
            )
            if assigned:
                injection["assigned_field_symbol_id"] = field_ids.get(
                    owner + "." + assigned.group(1)
                )
            injections.append(injection)

    entries = []
    for chunk in java_chunks:
        if chunk.chunk_type != "method" or len(chunk.symbol_ids) != 1:
            continue
        for marker, kind in _ENTRY_MARKERS.items():
            annotation = re.search(r"@" + marker + r"\b(?:\s*\(([^)]*)\))?", chunk.content)
            if annotation:
                entries.append({
                    "symbol_id": str(chunk.symbol_ids[0]), "kind": kind,
                    "marker": "@" + marker, "value": _annotation_value(annotation.group(1)),
                    "path": chunk.relative_path, "line": chunk.start_line,
                })
    return {
        "beans": beans, "injections": injections, "entries": entries,
        "reflections": _reflection_calls(java_chunks),
    }


def _default_bean_name(full_name):
    short = full_name.rsplit(".", 1)[-1]
    return short[:1].lower() + short[1:]


def _erase_type(value):
    return value.split("<", 1)[0].strip().rsplit(".", 1)[-1]


def _injection(symbol_id, point_kind, requested_type, qualifier, bean_by_type,
               parameter_index=None, parameter_name=None):
    candidates = list(bean_by_type.get(_erase_type(requested_type), []))
    if qualifier:
        candidates = [bean for bean in candidates if qualifier == bean["bean_name"]
                      or qualifier in bean["qualifiers"]]
    elif len([bean for bean in candidates if bean["primary"]]) == 1:
        candidates = [bean for bean in candidates if bean["primary"]]
    return {
        "injection_point_symbol_id": symbol_id,
        "point_kind": point_kind,
        "parameter_index": -1 if parameter_index is None else parameter_index,
        "parameter_name": parameter_name,
        "assigned_field_symbol_id": None,
        "requested_type": _erase_type(requested_type),
        "qualifier": qualifier,
        "bean_symbol_ids": [bean["symbol_id"] for bean in candidates],
        "status": ("CONDITIONAL" if len(candidates) == 1 and candidates[0]["conditional"]
                   else "RESOLVED") if len(candidates) == 1 else (
            "AMBIGUOUS" if candidates else "UNRESOLVED"),
    }


def _callable_owner(chunk):
    return chunk.symbol_names[0].split("(", 1)[0].rsplit(".", 1)[0]


def _parameters(chunk):
    callable_name = chunk.symbol_names[0].split("(", 1)[0].rsplit(".", 1)[-1]
    header = chunk.content.split("{", 1)[0]
    match = re.search(rf"\b{re.escape(callable_name)}\s*\(", header)
    if not match:
        return []
    start = match.end()
    depth = 1
    end = start
    while end < len(header) and depth:
        if header[end] == "(":
            depth += 1
        elif header[end] == ")":
            depth -= 1
        end += 1
    if depth:
        return []
    result = []
    for raw in _split_parameters(header[start:end - 1]):
        qualifier = next((value for _, value in _QUALIFIER.findall(raw)), None)
        clean = re.sub(r"@[\w.$]+(?:\s*\([^)]*\))?", " ", raw)
        clean = re.sub(r"\bfinal\b", " ", clean).strip()
        parameter = re.search(r"([\w.$<>?, \[\]]+)\s+(\w+)\s*$", clean)
        if parameter:
            result.append({"type": parameter.group(1).strip(),
                           "name": parameter.group(2), "qualifier": qualifier})
    return result


def _split_parameters(value):
    parts, start, depth = [], 0, 0
    for index, character in enumerate(value):
        if character in "<([{":
            depth += 1
        elif character in ">)]}":
            depth -= 1
        elif character == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    return parts + ([tail] if tail else [])


def _annotation_value(arguments):
    if not arguments:
        return None
    match = re.search(r"[\"']([^\"']+)[\"']", arguments)
    return match.group(1) if match else None


def _reflection_calls(chunks):
    """解析类名和方法名都是源码常量的常见反射链。"""
    methods = [chunk for chunk in chunks if chunk.chunk_type == "method"
               and len(chunk.symbol_ids) == 1]
    result = []
    direct = re.compile(
        r"Class\s*\.\s*forName\s*\(\s*[\"']([\w.$]+)[\"']\s*\)"
        r"[\s\S]{0,500}?\.\s*get(?:Declared)?Method\s*\(\s*[\"']([\w$]+)[\"']"
        r"[\s\S]{0,500}?\.\s*invoke\s*\("
    )
    for caller in methods:
        for match in direct.finditer(caller.content):
            owner, method_name = match.groups()
            targets = [str(target.symbol_ids[0]) for target in methods
                       if target.symbol_names[0].split("(", 1)[0] == owner + "." + method_name]
            line = caller.start_line + caller.content[:match.start()].count("\n")
            result.append({
                "caller_symbol_id": str(caller.symbol_ids[0]),
                "callee_symbol_ids": targets if len(targets) == 1 else [],
                "class_name": owner, "method_name": method_name,
                "path": caller.relative_path, "line": line,
                "status": "RESOLVED" if len(targets) == 1 else (
                    "AMBIGUOUS" if targets else "UNRESOLVED"),
                "reason": None if len(targets) == 1 else (
                    "MULTIPLE_REFLECTION_TARGETS" if targets else "REFLECTION_TARGET_NOT_IN_SNAPSHOT"),
            })
    return result
