// 仅用于测试审计系统的合成代码，不是生产项目。
@RestController
public class OrderController {
    private final OrderService service;

    OrderController(OrderService service) {
        this.service = service;
    }

    @GetMapping("/orders/{orderId}")
    public Order get(@AuthenticationPrincipal long principalUserId, @PathVariable long orderId) {
        return service.fetch(principalUserId, orderId);
    }
}
