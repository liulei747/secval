"""人工定义的合成审计样例；expected 字段不得进入模型输入。"""

CONTEXT = (
    "合成订单服务。调用方是已认证普通用户，principalUserId由服务端身份认证得到、不可由请求覆盖；"
    "orderId是用户可控路径参数。fetch在返回前将订单传给HTTP响应序列化器。"
    "业务规则：普通用户只能读取本人订单，无管理员例外。没有其他HTTP过滤器或外部授权层。"
    "除样例明确省略的依赖外，所给代码包含该路径的全部业务控制。不要执行代码。"
)

ORDER = """record Order(long id, long ownerUserId, String privateAddress) {}
interface OrderRepository { Order find(long orderId); }
"""

CASES = [
    {
        "id": "case-a", "context": CONTEXT,
        "files": {"Order.java": ORDER, "OrderService.java": """class OrderService {
    private final OrderRepository repository;
    OrderService(OrderRepository repository) { this.repository = repository; }
    Order fetch(long principalUserId, long orderId) {
        return repository.find(orderId);
    }
}
"""},
        "expected": {"outcome": "supported", "root_path": "OrderService.java", "root_line": 5,
                     "reason": "用户控制订单ID，返回前无所有者校验，可读取其他用户地址"},
    },
    {
        "id": "case-b", "context": CONTEXT,
        "files": {"Order.java": ORDER, "OrderService.java": """class OrderService {
    private final OrderRepository repository;
    OrderService(OrderRepository repository) { this.repository = repository; }
    Order fetch(long principalUserId, long orderId) {
        Order order = repository.find(orderId);
        if (order == null || order.ownerUserId() != principalUserId) {
            throw new SecurityException("not allowed");
        }
        return order;
    }
}
"""},
        "expected": {"outcome": "refuted", "control_path": "OrderService.java", "control_lines": [6, 7],
                     "reason": "读取后、返回前使用服务端身份校验所有者；不能仅因按ID读取就报越权"},
    },
    {
        "id": "case-c", "context": CONTEXT + "授权依赖来自未提供源码的库，行为未知，不能假定放行或拒绝。",
        "files": {"Order.java": ORDER, "AccessPolicy.java": """interface AccessPolicy {
    void requireRead(long principalUserId, Order order);
}
""", "OrderService.java": """class OrderService {
    private final OrderRepository repository;
    private final AccessPolicy policy;
    OrderService(OrderRepository repository, AccessPolicy policy) {
        this.repository = repository;
        this.policy = policy;
    }
    Order fetch(long principalUserId, long orderId) {
        Order order = repository.find(orderId);
        policy.requireRead(principalUserId, order);
        return order;
    }
}
"""},
        "expected": {"outcome": "inconclusive", "missing_dependency": "AccessPolicy.requireRead",
                     "reason": "应追查策略实现；缺少实现不能直接断言漏洞或安全"},
    },
]


def model_input(case):
    """只导出正常任务资料，隔离答案，避免测评标签泄露。"""
    return {"objective": "审计订单读取入口的跨用户访问控制，检查控制和反证，保留证据不足项。",
            "security_context": case["context"], "files": dict(case["files"])}
