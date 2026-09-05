"""用固定规则查找常见 Web 框架入口，只返回位置线索。"""

import re

from secval.code_processing.repository_scan import is_supported_source
from secval.models.audit_scope import in_scope


JAVA_MARKERS = {
    "spring": {
        "@RestController": "controller", "@Controller": "controller",
        "@RequestMapping": "route", "@GetMapping": "route", "@PostMapping": "route",
        "@PutMapping": "route", "@DeleteMapping": "route", "@PatchMapping": "route",
    },
    "jax_rs": {
        "@Path": "route", "@GET": "route", "@POST": "route", "@PUT": "route",
        "@DELETE": "route", "@PATCH": "route",
    },
}

PYTHON_ROUTE = re.compile(
    r"^\s*@\w+\.(get|post|put|delete|patch|options|head|route|websocket)\s*\("
)
DJANGO_ROUTE = re.compile(r"^\s*(path|re_path)\s*\(")


def find_framework_entries(source_store, snapshot_id, scope_paths, framework="all", limit=50):
    allowed = {"all", "spring", "jax_rs", "fastapi_flask", "django"}
    if framework not in allowed:
        raise ValueError("不支持的框架筛选")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("入口结果数量必须是1到100")

    results = []
    for offset in range(0, 10000, 100):
        rows = source_store.inventory(snapshot_id, offset)
        for row in rows:
            path = row["path"]
            if (row["status"] != "captured" or not is_supported_source(path)
                    or not in_scope(path, scope_paths)):
                continue
            content = source_store.read(snapshot_id, path)
            for line_number, line in enumerate(content.splitlines(), start=1):
                entry = _classify_line(path, line, line_number, framework)
                if entry is not None:
                    results.append(entry)
                    if len(results) == limit:
                        return results
        if len(rows) < 100:
            break
    return results


def _classify_line(path, line, line_number, framework):
    if path.lower().endswith(".java"):
        for name, markers in JAVA_MARKERS.items():
            if framework not in {"all", name}:
                continue
            for marker, kind in markers.items():
                # 标记后面不能继续跟标识符字符，避免
                # @ControllerAdvice 误命中 @Controller、@PathParam 误命中 @Path。
                if re.search(re.escape(marker) + r"(?![A-Za-z0-9_$])", line):
                    return {"framework": name, "kind": kind, "marker": marker,
                            "path": path, "line": line_number}
    if path.lower().endswith(".py"):
        if framework in {"all", "fastapi_flask"}:
            match = PYTHON_ROUTE.match(line)
            if match:
                return {"framework": "fastapi_flask", "kind": "route",
                        "marker": "@object." + match.group(1), "path": path,
                        "line": line_number}
        if framework in {"all", "django"}:
            match = DJANGO_ROUTE.match(line)
            if match:
                return {"framework": "django", "kind": "route",
                        "marker": match.group(1), "path": path, "line": line_number}
    return None
