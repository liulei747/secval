"""框架入口识别只返回固定快照中的位置线索。"""

from unittest.mock import MagicMock

import pytest

from secval.infrastructure.audit.framework_entry_finder import find_framework_entries
from secval.models.audit_contracts import ModelOutputError, ToolAction


def create_store():
    store = MagicMock()
    store.inventory.side_effect = [[
        {"path": "src/Orders.java", "status": "captured"},
        {"path": "api.py", "status": "captured"},
        {"path": "notes.txt", "status": "captured"},
    ]]
    store.read.side_effect = lambda snapshot, path: {
        "src/Orders.java": "@RestController\nclass Orders {\n@GetMapping(\"/orders\")\nvoid list() {}\n}",
        "api.py": "@router.post('/orders')\ndef create_order():\n    pass\n",
    }[path]
    return store


def test_finds_java_and_python_entries_without_returning_source():
    rows = find_framework_entries(create_store(), "source-1", [], limit=10)

    assert [(row["framework"], row["marker"]) for row in rows] == [
        ("spring", "@RestController"),
        ("spring", "@GetMapping"),
        ("fastapi_flask", "@object.post"),
    ]
    assert all("content" not in row for row in rows)


def test_framework_filter_and_scope_are_applied():
    rows = find_framework_entries(create_store(), "source-1", ["src"], "spring", 10)
    assert len(rows) == 2
    assert all(row["path"] == "src/Orders.java" for row in rows)


def test_tool_contract_rejects_unknown_framework():
    with pytest.raises(ModelOutputError, match="framework"):
        ToolAction.parse({"tool": "find_entry_points",
                          "arguments": {"framework": "unknown"}})


def test_similar_annotation_names_are_not_reported_as_routes():
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "Advice.java", "status": "captured"},
    ]
    store.read.return_value = "@ControllerAdvice\nclass Advice { @PathParam String id; }"

    assert find_framework_entries(store, "source-1", []) == []


def test_python_router_declaration_and_mount_are_found():
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "routes.py", "status": "captured"},
        {"path": "app.py", "status": "captured"},
    ]
    store.read.side_effect = lambda snapshot, path: {
        "routes.py": "router = APIRouter(prefix='/orders')\n"
                     "@router.get('/list')\ndef list_orders(): pass\n",
        "app.py": "from routes import router\napp.include_router(router)\n"
                     "app.register_blueprint(bp)\n",
    }[path]
    rows = find_framework_entries(store, "source-1", [], limit=10)
    markers = [(row["marker"], row["kind"]) for row in rows]
    assert ("router_declaration", "route") in markers
    assert ("router_mount", "route") in markers


def test_cross_language_process_calls_are_reported_as_clues():
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "bridge.py", "status": "captured"},
        {"path": "Bridge.java", "status": "captured"},
        {"path": "bridge.ts", "status": "captured"},
    ]
    store.read.side_effect = lambda snapshot, path: {
        "bridge.py": "subprocess.run(['java', '-jar', 'app.jar'])\n"
                     "os.system('java -jar x.jar')\n"
                     "subprocess.Popen(['ls'])\n",
        "Bridge.java": "new ProcessBuilder(\"python\", \"main.py\").start();\n"
                       "Runtime.getRuntime().exec(\"python main.py\");\n",
        "bridge.ts": "import { exec } from 'child_process';\n"
                     "exec('python main.py');\n"
                     "spawn('java', ['-jar', 'x.jar']);\n",
    }[path]
    rows = find_framework_entries(store, "source-1", [], limit=10)
    clues = [row for row in rows if row["kind"] == "cross_language_process"]
    # 每个调用点一行：Python 3 条、Java 2 条、Node 2 条。
    assert len(clues) == 7
    assert any(row["framework"] == "python" for row in clues)
    assert any(row["framework"] == "spring" for row in clues)
    assert any(row["framework"] in {"express_koa", "nestjs"} for row in clues)


def test_java_message_and_scheduler_entries_are_found():
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "src/Pipeline.java", "status": "captured"},
    ]
    store.read.return_value = (
        "@JmsListener(destination='q')\nvoid onJms() {}\n"
        "@KafkaListener(topics='t')\nvoid onKafka() {}\n"
        "@Scheduled(cron='0 * * * * *')\nvoid tick() {}\n"
        "@RocketMQMessageListener(topic='r')\nclass RocketConsumer {}\n"
    )
    rows = find_framework_entries(store, "source-1", [], limit=10)
    markers = [(row["marker"], row["kind"]) for row in rows]
    assert ("@JmsListener", "message_consumer") in markers
    assert ("@KafkaListener", "message_consumer") in markers
    assert ("@Scheduled", "scheduler") in markers
    assert ("@RocketMQMessageListener", "message_consumer") in markers


def test_python_middleware_boundaries_are_entries():
    """FastAPI/Flask与Django中间件在视图前生效，属于Python侧安全边界。"""

    store = MagicMock()
    store.inventory.return_value = [{"path": "main.py", "status": "captured"}]
    store.read.return_value = (
        'app.add_middleware(AuthMiddleware)\n'
        'app.middleware("http")(check_token)\n'
        'class TenantMiddleware:\n'
        '    def __init__(self, get_response): ...\n'
    )

    rows = find_framework_entries(store, "source-1", [])

    assert all(row["kind"] == "security_boundary" for row in rows)
    assert [row["line"] for row in rows] == [1, 2, 3]


def test_python_class_without_middleware_suffix_is_not_boundary():
    """普通类名不含Middleware时不误报，避免把业务类当授权层。"""

    store = MagicMock()
    store.inventory.return_value = [{"path": "order.py", "status": "captured"}]
    store.read.return_value = "class OrderService:\n    pass\n"

    assert find_framework_entries(store, "source-1", []) == []


def test_orders_safe_demo_route_is_found():
    """负样本demo的路由必须能被识别，保证refuted验收链路可复现。"""

    from pathlib import Path
    source = Path(__file__).parents[1] / "demo_projects" / "orders_safe" / "main.py"
    store = MagicMock()
    store.inventory.return_value = [{"path": "main.py", "status": "captured"}]
    store.read.side_effect = lambda snapshot, path: source.read_text(encoding="utf-8")

    rows = find_framework_entries(store, "source-1", [])

    assert [(row["marker"], row["kind"]) for row in rows] == [("@object.get", "route")]




def test_programmatic_route_registration_is_found():
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "api.py", "status": "captured"},
    ]
    store.read.return_value = (
        "app.add_url_rule('/flask', view_func=handle_flask)\n"
        "app.add_api_route('/fastapi', handle_fastapi)\n"
        "router.add_websocket_api_route('/ws', handle_ws)\n"
    )

    rows = find_framework_entries(store, "source-1", [])

    assert [row["marker"] for row in rows] == [
        "add_*_route", "add_*_route", "add_*_route"
    ]
    assert all(row["framework"] == "fastapi_flask" for row in rows)


def test_regular_python_calls_are_not_routes():
    store = MagicMock()
    store.inventory.return_value = [{"path": "api.py", "status": "captured"}]
    store.read.return_value = "service.add_record('not a route')\nx = 1\n"

    assert find_framework_entries(store, "source-1", []) == []


def test_nested_namespace_programmatic_registration_is_found():
    store = MagicMock()
    store.inventory.return_value = [{"path": "api.py", "status": "captured"}]
    store.read.return_value = "api.v1.add_api_route('/orders', create_order)\n"

    rows = find_framework_entries(store, "source-1", [])

    assert rows == [{"framework": "fastapi_flask", "kind": "route",
                     "marker": "add_*_route", "path": "api.py", "line": 1}]


def test_spring_bean_listener_and_router_function_entries_are_found():
    store = MagicMock()
    store.inventory.return_value = [{"path": "Config.java", "status": "captured"}]
    store.read.return_value = (
        "@Bean\n"
        "SecurityFilterChain filterChain(HttpSecurity http) { return null; }\n"
        "@EventListener\n"
        "void onEvent(AppEvent e) {}\n"
        "RouterFunction<ServerResponse> routes() {\n"
        "  return route(GET(\"/orders\"), handler);\n"
        "}\n"
        "@Scheduled(fixedDelay=1000)\n"
        "void poll() {}\n"
    )

    rows = find_framework_entries(store, "source-1", [])

    markers = [(row["marker"], row["kind"]) for row in rows]
    assert ("@Bean", "bean_definition") in markers
    assert ("@EventListener", "event_listener") in markers
    assert ("RouterFunction", "route") in markers
    assert ("@Scheduled", "scheduler") in markers


def test_spring_message_listeners_are_entries():
    store = MagicMock()
    store.inventory.return_value = [{"path": "Consumer.java", "status": "captured"}]
    store.read.return_value = "@KafkaListener(topics=\"t\")\nvoid onMsg(String m) {}\n"

    rows = find_framework_entries(store, "source-1", [])

    assert rows[0]["marker"] == "@KafkaListener"
    assert rows[0]["kind"] == "message_consumer"


def test_order_entry_demo_controller_is_found():
    """验收demo的入口必须能被识别；识别退化会让supported→独立复核链路失效。"""

    from pathlib import Path
    source = Path(__file__).parents[1] / "demo_projects" / "order_entry" / "OrderController.java"
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "OrderController.java", "status": "captured"},
        {"path": "OrderService.java", "status": "captured"},
    ]
    store.read.side_effect = lambda snapshot, path: source.read_text(encoding="utf-8") \
        if path == "OrderController.java" else "class OrderService {}\n"

    rows = find_framework_entries(store, "source-1", [], limit=10)

    assert [(row["marker"], row["kind"]) for row in rows] == [
        ("@RestController", "controller"), ("@GetMapping", "route")
    ]
    assert all(row["path"] == "OrderController.java" for row in rows)
def test_python_async_entries_are_found():
    store = MagicMock()
    store.inventory.return_value = [{"path": "tasks.py", "status": "captured"}]
    store.read.return_value = (
        "@celery.task\n"
        "def sync_data(): pass\n"
        "@shared_task\n"
        "def export_data(): pass\n"
        "@receiver(post_save, sender=Order)\n"
        "def on_order_save(sender, **kwargs): pass\n"
        "@app.on_event('startup')\n"
        "def startup(): pass\n"
    )

    rows = find_framework_entries(store, "source-1", [])

    markers = [row["marker"] for row in rows]
    assert markers == ["@task", "@shared_task", "@receiver", "@on_event"]
    assert all(row["kind"] == "async_entry" for row in rows)


def test_regular_python_decorators_are_not_async_entries():
    store = MagicMock()
    store.inventory.return_value = [{"path": "api.py", "status": "captured"}]
    store.read.return_value = "@app.get('/x')\ndef x(): pass\n@functools.lru_cache\ndef y(): pass\n"

    rows = find_framework_entries(store, "source-1", [])

    assert all(row["kind"] != "async_entry" for row in rows)

def test_servlet_and_spring_security_boundaries_are_entries():
    """过滤器/拦截器在请求到达控制器前生效；识别它们才能核对有效策略。"""

    store = MagicMock()
    store.inventory.return_value = [{"path": "AuthFilter.java", "status": "captured"}]
    store.read.return_value = (
        '@WebFilter("/*")\n'
        'public class AuthFilter implements Filter {\n'
        '    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {}\n'
        '}\n'
        'class JwtFilter extends OncePerRequestFilter {\n'
        '    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) {}\n'
        '}\n'
        'class AuditInterceptor implements HandlerInterceptor {\n'
        '    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object handler) { return true; }\n'
        '}\n'
    )

    rows = find_framework_entries(store, "source-1", [])

    assert all(row["kind"] == "security_boundary" for row in rows)
    assert all(row["framework"] == "spring" for row in rows)
    assert [row["line"] for row in rows] == [1, 2, 5, 8]


def test_implements_partial_name_is_not_security_boundary():
    """implements ResultSetFactory这类含Filter子串的名字不能误报。"""

    store = MagicMock()
    store.inventory.return_value = [{"path": "Repo.java", "status": "captured"}]
    store.read.return_value = "class Repo implements ResultSetFactory, Serializable { }\n"

    assert find_framework_entries(store, "source-1", []) == []


def test_javascript_routes_and_middleware_are_entries():
    store = MagicMock()
    store.inventory.return_value = [{"path": "server.js", "status": "captured"}]
    store.read.return_value = (
        "app.use(authMiddleware);\n"
        "router.get('/orders/:id', getOrder);\n"
        "api.v1.post('/orders', createOrder);\n"
        "service.getOrder('not a route registration');\n"
        "service.post('/not-a-router', value);\n"
    )

    rows = find_framework_entries(store, "source-1", [], "express_koa")

    assert [(row["marker"], row["kind"]) for row in rows] == [
        (".use", "security_boundary"),
        (".get", "route"),
        (".post", "route"),
    ]


def test_javascript_framework_filter_excludes_other_languages():
    rows = find_framework_entries(
        create_store(), "source-1", [], "express_koa", 10
    )
    assert rows == []


def test_orders_js_demo_route_and_middleware_are_found():
    """JavaScript验收demo必须同时暴露路由和中间件边界。"""

    from pathlib import Path
    source = Path(__file__).parents[1] / "demo_projects" / "orders_js" / "server.js"
    store = MagicMock()
    store.inventory.return_value = [{"path": "server.js", "status": "captured"}]
    store.read.return_value = source.read_text(encoding="utf-8")

    rows = find_framework_entries(store, "source-1", [], "express_koa")

    assert [(row["marker"], row["kind"]) for row in rows] == [
        (".use", "security_boundary"),
        (".get", "route"),
    ]


def test_nestjs_routes_async_entries_and_boundaries_are_found():
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "orders.controller.ts", "status": "captured"}
    ]
    store.read.return_value = (
        "@Controller('orders')\n"
        "@UseGuards(AuthGuard)\n"
        "@Get(':id')\n"
        "@MessagePattern('orders.created')\n"
        "@Cron('0 * * * *')\n"
        "class AuthMiddleware implements NestMiddleware {}\n"
    )

    rows = find_framework_entries(store, "source-1", [], "nestjs")

    assert [(row["marker"], row["kind"]) for row in rows] == [
        ("@Controller", "controller"),
        ("guard_or_middleware", "security_boundary"),
        ("@Get", "route"),
        ("@MessagePattern", "message_consumer"),
        ("@Cron", "scheduler"),
        ("guard_or_middleware", "security_boundary"),
    ]


def test_typescript_express_route_is_found_without_matching_service_call():
    store = MagicMock()
    store.inventory.return_value = [{"path": "server.ts", "status": "captured"}]
    store.read.return_value = (
        "orderRouter.post('/orders', createOrder);\n"
        "orderService.post('/not-a-route', value);\n"
    )

    rows = find_framework_entries(store, "source-1", [], "express_koa")

    assert [(row["marker"], row["line"]) for row in rows] == [(".post", 1)]


def test_nestjs_queue_and_interval_entries_are_found():
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "invoice.processor.ts", "status": "captured"},
    ]
    store.read.return_value = (
        "@Processor('invoice-queue')\n"
        "class InvoiceProcessor {\n"
        "  @Interval(5000)\n"
        "  sync() {}\n"
        "  @Timeout(1000)\n"
        "  warm() {}\n"
        "}\n"
    )
    rows = find_framework_entries(store, "source-1", [], "nestjs")
    assert [(row["marker"], row["kind"]) for row in rows] == [
        ("@Processor", "message_consumer"),
        ("@Interval", "scheduler"),
        ("@Timeout", "scheduler"),
    ]


def test_orders_ts_demo_nestjs_entries_are_found():
    """TypeScript验收demo必须暴露控制器、Guard和HTTP路由。"""

    from pathlib import Path
    source = (
        Path(__file__).parents[1] / "demo_projects" / "orders_ts"
        / "orders.controller.ts"
    )
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "orders.controller.ts", "status": "captured"}
    ]
    store.read.return_value = source.read_text(encoding="utf-8")

    rows = find_framework_entries(store, "source-1", [], "nestjs")

    assert [(row["marker"], row["kind"]) for row in rows] == [
        ("@Controller", "controller"),
        ("guard_or_middleware", "security_boundary"),
        ("@Get", "route"),
    ]



def test_order_entry_demo_boundary_files_are_recognized():
    """验收demo里的边界与业务类必须区分：过滤器命中，控制器按注解识别。"""

    from pathlib import Path
    demo = Path(__file__).parents[1] / "demo_projects" / "order_entry"
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "AuthConfig.java", "status": "captured"},
        {"path": "OrderController.java", "status": "captured"},
    ]
    store.read.side_effect = lambda snapshot, path: (demo / path).read_text(encoding="utf-8")

    rows = find_framework_entries(store, "source-1", [])

    by_file = {path: [(row["marker"], row["kind"]) for row in rows if row["path"] == path]
               for path in ("AuthConfig.java", "OrderController.java")}
    # AuthConfig的authFilter方法返回Filter类型，命中安全边界。
    assert ("filter_or_interceptor", "security_boundary") in by_file["AuthConfig.java"]
    # 控制器仍按注解识别，两者互不干扰。
    assert ("@RestController", "controller") in by_file["OrderController.java"]
    assert ("@GetMapping", "route") in by_file["OrderController.java"]


def test_orders_api_python_middleware_is_found():
    """Python验收demo的中间件与路由必须能被识别；退化会让Python侧链路失效。"""

    from pathlib import Path
    demo = Path(__file__).parents[1] / "demo_projects" / "orders_api"
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "main.py", "status": "captured"},
        {"path": "auth.py", "status": "captured"},
    ]
    store.read.side_effect = lambda snapshot, path: (demo / path).read_text(encoding="utf-8")

    rows = find_framework_entries(store, "source-1", [])

    main_rows = [row for row in rows if row["path"] == "main.py"]
    # 顺序不敏感：main.py应同时命中路由和中间件安全边界。
    assert sorted((row["marker"], row["kind"]) for row in main_rows) == [
        ("@object.get", "route"), ("middleware", "security_boundary")
    ]



def test_java_method_authorization_annotations_are_found():
    store = MagicMock()
    store.inventory.return_value = [{"path": "Admin.java", "status": "captured"}]
    store.read.return_value = (
        "@PreAuthorize(\"hasRole('ADMIN')\")\n"
        "void deleteAll() {}\n"
        "    @SaCheckPermission(\"order:write\")\n"
        "    void write() {}\n"
        "    @RequiresRoles(\"manager\")\n"
        "    void approve() {}\n"
    )

    rows = find_framework_entries(store, "source-1", [])

    auth_rows = [row for row in rows if row["kind"] == "authorization"]
    assert [row["marker"] for row in auth_rows] == [
        "@PreAuthorize", "@SaCheckPermission", "@RequiresRoles"
    ]
    assert [row["line"] for row in auth_rows] == [1, 3, 5]


def test_python_authorization_decorators_are_found():
    store = MagicMock()
    store.inventory.return_value = [{"path": "admin.py", "status": "captured"}]
    store.read.return_value = (
        "@login_required\n"
        "def dashboard(): ...\n"
        "    @require_permission(\"order:read\")\n"
        "    def read(): ...\n"
        "    @authorize\n"
        "    def list_users(): ...\n"
    )

    rows = find_framework_entries(store, "source-1", [])

    auth_rows = [row for row in rows if row["kind"] == "authorization"]
    assert [row["marker"] for row in auth_rows] == [
        "login_required", "require_permission", "authorize"
    ]


def test_java_authorization_annotation_prefix_is_not_misdetected():
    store = MagicMock()
    store.inventory.return_value = [{"path": "Weird.java", "status": "captured"}]
    store.read.return_value = "@PreAuthorizeX\nclass Weird {}\n"

    assert find_framework_entries(store, "source-1", []) == []
