"""用固定规则查找常见 Web 框架入口，只返回位置线索。"""

import re

from secval.code_processing.repository_scan import is_supported_source
from secval.models.audit_scope import in_scope


JAVA_MARKERS = {
    "spring": {
        "@RestController": "controller", "@Controller": "controller",
        "@RequestMapping": "route", "@GetMapping": "route", "@PostMapping": "route",
        "@PutMapping": "route", "@DeleteMapping": "route", "@PatchMapping": "route",
        "@Bean": "bean_definition", "@EventListener": "event_listener",
        "@MessageMapping": "route", "@KafkaListener": "message_consumer",
        "@RabbitListener": "message_consumer", "@Scheduled": "scheduler",
        "@JmsListener": "message_consumer", "@StreamListener": "message_consumer",
        "@ServiceActivator": "message_consumer", "@InboundChannelAdapter": "message_consumer",
        "@SqsListener": "message_consumer", "@RocketMQMessageListener": "message_consumer",
    },
    "jax_rs": {
        "@Path": "route", "@GET": "route", "@POST": "route", "@PUT": "route",
        "@DELETE": "route", "@PATCH": "route",
    },
}
JAVA_PROGRAMMATIC_ROUTE = re.compile(
    r"\bRouterFunction\s*<"
    r"|\broute\s*\(\s*(GET|POST|PUT|DELETE|PATCH)\b"
)
# 过滤器/拦截器：安全控制常在请求到达控制器前生效，属于入口边界的一部分。
JAVA_SECURITY_BOUNDARY = re.compile(
    r"@WebFilter\b"
    r"|\bFilter\s+\w+\s*\(\s*\)"
    r"|\bimplements\s+(?:[A-Za-z0-9_$.]+\s*,\s*)*Filter\b"
    r"|\bextends\s+(?:[A-Za-z0-9_$.]+\.)?OncePerRequestFilter\b"
    r"|\bimplements\s+(?:[A-Za-z0-9_$.]+\s*,\s*)*HandlerInterceptor\b"
    r"|\bextends\s+(?:[A-Za-z0-9_$.]+\.)?HandlerInterceptorAdapter\b"
)

# 方法级授权注解：模型核对"有效策略"时需要区分哪些方法已声明授权要求。
# 只识别注解本身，不推断注解语义是否正确；表达式与角色名必须回读源码核实。
JAVA_AUTHORIZATION = re.compile(
    r"@PreAuthorize\b|@PostAuthorize\b|@Secured\b|@RolesAllowed\b"
    r"|@PermitAll\b|@DenyAll\b|@SaCheckLogin\b|@SaCheckRole\b|@SaCheckPermission\b"
    r"|@RequiresPermissions\b|@RequiresRoles\b"
)

PYTHON_ROUTE = re.compile(
    r"^\s*@\w+\.(get|post|put|delete|patch|options|head|route|websocket)\s*\("
)
DJANGO_ROUTE = re.compile(r"^\s*(path|re_path)\s*\(")
PYTHON_ASYNC_ENTRY = re.compile(
    r"^\s*@(?:\w+\.)?(task|shared_task|receiver|on_event)\b"
)
# Python授权装饰器：与Java方法级注解同类，只报位置，不判断保护是否生效。
PYTHON_AUTHORIZATION = re.compile(
    r"^\s*@\w+\.(login_required|permission_required|staff_member_required)\b"
    r"|^\s*@(login_required|permission_required|staff_member_required)\b"
    r"|^\s*@requires_auth\b|^\s*@requires_permission\b|^\s*@authorize\b"
    r"|^\s*@(require_permission|require_role|require_auth)\b"
    r"|^\s*@\w+\.(require_permission|require_role|require_auth)\b"
)
# 程序式注册：Flask add_url_rule、FastAPI add_api_route/add_websocket_api_route。
PYTHON_ROUTER_DECLARATION = re.compile(
    r"^\s*\w+\s*=\s*(?:APIRouter|Blueprint)\s*\("
)
PYTHON_ROUTER_MOUNT = re.compile(
    r"^\s*\w+\.(?:include_router|register_blueprint)\s*\("
)
# 跨语言进程调用线索：一种语言通过子进程调用另一种语言的可执行入口，
# 是命令注入跨语言传播的候选路径；只报位置，不构成 CALLS 边。
PYTHON_CROSS_LANGUAGE = re.compile(
    r"\bsubprocess\.(?:run|call|check_call|check_output|Popen)\b"
    r"|\bos\.(?:system|popen|execv\w*)\b"
)
JAVA_CROSS_LANGUAGE = re.compile(
    r"\bnew\s+ProcessBuilder\b|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\b"
)
NODE_CROSS_LANGUAGE = re.compile(
    r"\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\("
)
PROGRAMMATIC_ROUTE = re.compile(
    r"^\s*\w+(?:\.\w+)*\.(add_url_rule|add_api_route|add_websocket_api_route)\s*\("
)
# Python中间件：请求到达视图前生效的授权/过滤层，与Java过滤器同属安全边界。
PYTHON_SECURITY_BOUNDARY = re.compile(
    r"^\s*\w+(?:\.\w+)*\.(add_middleware|middleware)\s*\("
    r"|\bclass\s+\w+Middleware\b"
)
JAVASCRIPT_ROUTE = re.compile(
    r"^\s*(?:app|router|api|server|[A-Za-z_$][A-Za-z0-9_$]*(?:app|router|api|server))"
    r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
    r"\.(get|post|put|delete|patch|options|head|all)\s*\(",
    re.IGNORECASE,
)
JAVASCRIPT_MIDDLEWARE = re.compile(
    r"^\s*(?:app|router|api|server|[A-Za-z_$][A-Za-z0-9_$]*(?:app|router|api|server))"
    r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\.use\s*\(",
    re.IGNORECASE,
)
NESTJS_ENTRY = re.compile(
    r"^\s*@(Controller|Get|Post|Put|Delete|Patch|Options|Head|All|"
    r"MessagePattern|EventPattern|Cron|Processor|Interval|Timeout)\b"
)
NESTJS_SECURITY_BOUNDARY = re.compile(
    r"^\s*@UseGuards\b|\bimplements\s+NestMiddleware\b"
)


def find_framework_entries(source_store, snapshot_id, scope_paths, framework="all", limit=50):
    allowed = {
        "all", "spring", "jax_rs", "fastapi_flask", "django", "express_koa",
        "nestjs"
    }
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
        if framework in {"all", "spring"} and JAVA_PROGRAMMATIC_ROUTE.search(line):
            return {"framework": "spring", "kind": "route", "marker": "RouterFunction",
                    "path": path, "line": line_number}
        if framework in {"all", "spring"} and JAVA_SECURITY_BOUNDARY.search(line):
            return {"framework": "spring", "kind": "security_boundary", "marker": "filter_or_interceptor",
                    "path": path, "line": line_number}
        if framework in {"all", "spring"} and JAVA_AUTHORIZATION.search(line):
            match = JAVA_AUTHORIZATION.search(line)
            return {"framework": "spring", "kind": "authorization", "marker": match.group(0),
                    "path": path, "line": line_number}
        if framework in {"all", "spring"} and JAVA_CROSS_LANGUAGE.search(line):
            match = JAVA_CROSS_LANGUAGE.search(line)
            return {"framework": "spring", "kind": "cross_language_process",
                    "marker": match.group(0), "path": path, "line": line_number}
    if path.lower().endswith(".py"):
        if framework in {"all", "fastapi_flask"}:
            match = PYTHON_ROUTE.match(line)
            if match:
                return {"framework": "fastapi_flask", "kind": "route",
                        "marker": "@object." + match.group(1), "path": path,
                        "line": line_number}
            if PYTHON_ROUTER_DECLARATION.match(line):
                return {"framework": "fastapi_flask", "kind": "route",
                        "marker": "router_declaration", "path": path,
                        "line": line_number}
            if PYTHON_ROUTER_MOUNT.match(line):
                return {"framework": "fastapi_flask", "kind": "route",
                        "marker": "router_mount", "path": path,
                        "line": line_number}
            if PROGRAMMATIC_ROUTE.match(line):
                return {"framework": "fastapi_flask", "kind": "route",
                        "marker": "add_*_route", "path": path,
                        "line": line_number}
        if framework in {"all", "django"}:
            match = DJANGO_ROUTE.match(line)
            if match:
                return {"framework": "django", "kind": "route",
                        "marker": match.group(1), "path": path, "line": line_number}
        if framework in {"all", "fastapi_flask", "django"}:
            match = PYTHON_ASYNC_ENTRY.match(line)
            if match:
                return {"framework": "fastapi_flask", "kind": "async_entry",
                        "marker": "@" + match.group(1), "path": path,
                        "line": line_number}
        if framework in {"all", "fastapi_flask", "django"}:
            match = PYTHON_SECURITY_BOUNDARY.search(line)
            if match and (".middleware(" in line or "Middleware" in line):
                return {"framework": "django" if framework == "django" else "fastapi_flask",
                        "kind": "security_boundary", "marker": "middleware",
                        "path": path, "line": line_number}
        if framework in {"all", "fastapi_flask", "django"}:
            match = PYTHON_AUTHORIZATION.match(line)
            if match:
                marker = match.group(0).strip().lstrip("@")
                return {"framework": "fastapi_flask", "kind": "authorization", "marker": marker,
                        "path": path, "line": line_number}
        match = PYTHON_CROSS_LANGUAGE.search(line)
        if match:
            return {"framework": "python", "kind": "cross_language_process",
                    "marker": match.group(0), "path": path, "line": line_number}
    lower_path = path.lower()
    if lower_path.endswith((".js", ".ts", ".tsx")) and framework in {
        "all", "express_koa"
    }:
        match = NODE_CROSS_LANGUAGE.search(line)
        if match:
            return {"framework": "express_koa", "kind": "cross_language_process",
                    "marker": match.group(0), "path": path, "line": line_number}
        route = JAVASCRIPT_ROUTE.match(line)
        if route:
            return {
                "framework": "express_koa",
                "kind": "route",
                "marker": "." + route.group(1),
                "path": path,
                "line": line_number,
            }
        if JAVASCRIPT_MIDDLEWARE.match(line):
            return {
                "framework": "express_koa",
                "kind": "security_boundary",
                "marker": ".use",
                "path": path,
                "line": line_number,
            }
    if lower_path.endswith((".ts", ".tsx")) and framework in {"all", "nestjs"}:
        match = NODE_CROSS_LANGUAGE.search(line)
        if match:
            return {"framework": "nestjs", "kind": "cross_language_process",
                    "marker": match.group(0), "path": path, "line": line_number}
        nest_entry = NESTJS_ENTRY.match(line)
        if nest_entry:
            marker_name = nest_entry.group(1)
            if marker_name == "Controller":
                kind = "controller"
            elif marker_name in {"MessagePattern", "EventPattern"}:
                kind = "message_consumer"
            elif marker_name == "Cron":
                kind = "scheduler"
            elif marker_name == "Processor":
                kind = "message_consumer"
            elif marker_name in {"Interval", "Timeout"}:
                kind = "scheduler"
            else:
                kind = "route"
            return {
                "framework": "nestjs",
                "kind": kind,
                "marker": "@" + marker_name,
                "path": path,
                "line": line_number,
            }
        if NESTJS_SECURITY_BOUNDARY.search(line):
            return {
                "framework": "nestjs",
                "kind": "security_boundary",
                "marker": "guard_or_middleware",
                "path": path,
                "line": line_number,
            }
    return None
